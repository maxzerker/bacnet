package bacnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// SubscribeCOV establishes a Change of Value (COV) subscription with a BACnet device.
// It returns a channel for COV notifications and a channel for errors during the subscription lifecycle.
// The subscription will automatically re-subscribe before the lifetime expires.
// The context can be used to cancel the subscription.
func (c *BACnetClient) SubscribeCOV(ctx context.Context, device DeviceInfo, object BACnetObject, subscriberProcessIdentifier uint32, issueConfirmedNotifications bool, lifetime uint8) (<-chan COVNotification, <-chan error) {
	covChan := make(chan COVNotification)
	errChan := make(chan error, 1) // Buffered to prevent goroutine leak if no one reads the error

	go func() {
		defer close(covChan)
		defer close(errChan)

		// Initial subscription
		err := c.sendSubscribeCOVRequest(device, object, subscriberProcessIdentifier, issueConfirmedNotifications, lifetime)
		if err != nil {
			errChan <- fmt.Errorf("initial SubscribeCOV failed: %w", err)
			return
		}

		// Start listening for COV notifications and handle re-subscriptions
		c.handleCOVSubscription(ctx, device, object, subscriberProcessIdentifier, issueConfirmedNotifications, lifetime, covChan, errChan)
	}()

	return covChan, errChan
}

// sendSubscribeCOVRequest sends a single SubscribeCOV request and waits for the Simple-ACK.
func (c *BACnetClient) sendSubscribeCOVRequest(device DeviceInfo, object BACnetObject, subscriberProcessIdentifier uint32, issueConfirmedNotifications bool, lifetime uint8) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Construct SubscribeCOV request
	var apduBuffer bytes.Buffer

	// APDU (Confirmed-Request)
	apduBuffer.WriteByte(APDU_CONFIRMED_REQUEST | 0x02) // APDU Type (0x00) | PDU Flags (0x02)
	apduBuffer.WriteByte(0x75)                          // Max segments (7) | Max APDU (5)
	invokeID := GInvokeIDManager.Next()
	apduBuffer.WriteByte(invokeID) // Invoke ID
	apduBuffer.WriteByte(SERVICE_CONFIRMED_SUBSCRIBE_COV)

	// Subscriber Process Identifier
	apduBuffer.WriteByte(0x09) // Tag 0, context-specific, length 1
	apduBuffer.WriteByte(byte(subscriberProcessIdentifier))

	// Monitored Object Identifier
	apduBuffer.WriteByte(0x1C) // Tag 1, context-specific, length 4
	monitoredObjectIdentifier := (uint32(object.Type) << 22) | object.Instance
	binary.Write(&apduBuffer, binary.BigEndian, monitoredObjectIdentifier)

	// Issue Confirmed Notifications
	apduBuffer.WriteByte(0x29) // Tag 2, context-specific, length 1
	if issueConfirmedNotifications {
		apduBuffer.WriteByte(1)
	} else {
		apduBuffer.WriteByte(0)
	}

	// Lifetime
	apduBuffer.WriteByte(0x39) // Tag 3, context-specific, length 1
	apduBuffer.WriteByte(byte(lifetime))

	var buffer bytes.Buffer
	// BVLC Header
	bvlc := BVLCHeader{
		Type:     BVLC_TYPE_BACNET_IP,
		Function: BVLC_ORIGINAL_UNICAST_NPDU,
		Length:   uint16(4 + 2 + apduBuffer.Len()),
	}
	binary.Write(&buffer, binary.BigEndian, &bvlc)

	// NPDU
	npdu := NPDU{
		Version: 1,
		Control: 0x04, // Expecting Reply
	}
	binary.Write(&buffer, binary.BigEndian, &npdu)

	// APDU
	buffer.Write(apduBuffer.Bytes())

	// Send SubscribeCOV packet
	_, err := c.conn.WriteTo(buffer.Bytes(), &net.UDPAddr{IP: device.IPAddress, Port: device.Port})
	if err != nil {
		return fmt.Errorf("failed to send SubscribeCOV packet: %w", err)
	}

	// Listen for Simple-ACK response
	c.conn.SetReadDeadline(time.Now().Add(c.options.Timeout))
	readBuffer := make([]byte, 2048)

	n, _, err := c.conn.ReadFromUDP(readBuffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("timeout waiting for SubscribeCOV response")
		}
		return fmt.Errorf("failed to read from UDP: %w", err)
	}

	// Parse Simple-ACK
	r := bytes.NewReader(readBuffer[:n])
	// BVLC & NPDU - skip
	r.Seek(6, 0)
	apduType, _ := r.ReadByte()
	if apduType&0xF0 != APDU_SIMPLE_ACK {
		return fmt.Errorf("not a Simple-ACK, got %x", apduType)
	}
	respInvokeID, _ := r.ReadByte()
	if respInvokeID != invokeID {
		return fmt.Errorf("invoke ID mismatch: expected %d, got %d", invokeID, respInvokeID)
	}

	return nil
}

// handleCOVSubscription manages the COV subscription lifecycle, including re-subscriptions and notification listening.
func (c *BACnetClient) handleCOVSubscription(ctx context.Context, device DeviceInfo, object BACnetObject, subscriberProcessIdentifier uint32, issueConfirmedNotifications bool, lifetime uint8, covChan chan<- COVNotification, errChan chan<- error) {
	// Calculate re-subscription interval (e.g., 80% of lifetime)
	reSubscribeInterval := time.Duration(float64(lifetime)*0.8) * time.Second
	if reSubscribeInterval <= 0 { // Ensure a minimum interval if lifetime is very small or zero
		reSubscribeInterval = 1 * time.Second
	}

	ticker := time.NewTicker(reSubscribeInterval)
	defer ticker.Stop()

	readBuffer := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return // Context cancelled, terminate goroutine
		case <-ticker.C:
			// Time to re-subscribe
			err := c.sendSubscribeCOVRequest(device, object, subscriberProcessIdentifier, issueConfirmedNotifications, lifetime)
			if err != nil {
				errChan <- fmt.Errorf("re-subscription failed: %w", err)
				return // Terminate on re-subscription failure
			}
		case <-time.After(100 * time.Millisecond): // Small timeout to allow reading from UDP
			// Attempt to read COV notifications
			c.mu.Lock()
			c.conn.SetReadDeadline(time.Now().Add(c.options.Timeout))
			n, _, err := c.conn.ReadFromUDP(readBuffer)
			c.mu.Unlock()

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout, no data, try again
				}
				errChan <- fmt.Errorf("error reading COV notification: %w", err)
				return // Terminate on read error
			}

			notification, err := parseCOVNotification(readBuffer[:n])
			if err == nil {
				covChan <- notification
			} else {
				errChan <- fmt.Errorf("error parsing COV notification: %w", err)
			}
		}
	}
}
