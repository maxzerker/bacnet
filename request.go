package bacnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// WhoIs sends a WhoIs request and returns a list of discovered devices.
func WhoIs(conn *net.UDPConn, broadcastAddr *net.UDPAddr, timeout time.Duration) ([]DeviceInfo, error) {

	// Construct WhoIs packet
	var buffer bytes.Buffer

	// BVLC Header
	bvlc := BVLCHeader{
		Type:     BVLC_TYPE_BACNET_IP,
		Function: BVLC_ORIGINAL_BROADCAST_NPDU,
		Length:   8, // BVLC(4) + NPDU(2) + APDU(2)
	}
	binary.Write(&buffer, binary.BigEndian, &bvlc)

	// NPDU
	npdu := NPDU{
		Version: 1,
		Control: NPDU_CONTROL_NORMAL_MESSAGE,
	}
	binary.Write(&buffer, binary.BigEndian, &npdu)

	// APDU (Unconfirmed-Request, Who-Is)
	buffer.WriteByte(APDU_UNCONFIRMED_REQUEST)
	buffer.WriteByte(SERVICE_UNCONFIRMED_WHO_IS)
	// No parameters for Who-Is

	// Send WhoIs packet
	_, err := conn.WriteTo(buffer.Bytes(), broadcastAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send WhoIs packet: %w", err)
	}

	// Listen for I-Am responses
	var devices []DeviceInfo
	conn.SetReadDeadline(time.Now().Add(timeout))
	readBuffer := make([]byte, 1500)

	for {
		n, addr, err := conn.ReadFromUDP(readBuffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break // Timeout reached
			}
			return nil, fmt.Errorf("failed to read from UDP: %w", err)
		}

		device, err := parseIAm(readBuffer[:n], *addr)
		if err == nil {
			devices = append(devices, device)
		}
	}

	return devices, nil
}

// GetObjectList retrieves the object list from a device.
func (c *BACnetClient) GetObjectList(device DeviceInfo) ([]BACnetObject, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Construct ReadProperty request for object-list
	var apduBuffer bytes.Buffer

	// APDU (Confirmed-Request)
	apduBuffer.WriteByte(APDU_CONFIRMED_REQUEST | 0x02) // APDU Type (0x00) | PDU Flags (0x02)
	apduBuffer.WriteByte(0x75)                          // Max segments (7) | Max APDU (5)
	invokeID := GInvokeIDManager.Next()
	apduBuffer.WriteByte(invokeID) // Invoke ID
	apduBuffer.WriteByte(SERVICE_CONFIRMED_READ_PROPERTY)

	// Context-specific tags for ReadProperty
	// Object Identifier (Device Object)
	apduBuffer.WriteByte(0x0C) // Tag 0, context-specific, length 4
	objectIdentifier := (uint32(OBJECT_DEVICE) << 22) | device.DeviceID
	binary.Write(&apduBuffer, binary.BigEndian, objectIdentifier)

	// Property Identifier (Object List)
	apduBuffer.WriteByte(0x19) // Tag 1, context-specific, length 1
	apduBuffer.WriteByte(byte(PROP_OBJECT_LIST))

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

	// Send ReadProperty packet
	_, err := c.conn.WriteTo(buffer.Bytes(), &net.UDPAddr{IP: device.IPAddress, Port: device.Port})
	if err != nil {
		return nil, fmt.Errorf("failed to send ReadProperty packet: %w", err)
	}

	// Listen for Complex-ACK response
	c.conn.SetReadDeadline(time.Now().Add(c.options.Timeout))
	readBuffer := make([]byte, 2048)

	n, _, err := c.conn.ReadFromUDP(readBuffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("timeout waiting for ReadProperty response")
		}
		return nil, fmt.Errorf("failed to read from UDP: %w", err)
	}

	return parseObjectList(readBuffer[:n], invokeID)
}

func (c *BACnetClient) GetObjectAllPropertyList(device DeviceInfo, object BACnetObject) ([]BACnetPropertyValue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Construct ReadPropertyMultiple request
	var apduBuffer bytes.Buffer

	// APDU (Confirmed-Request)
	apduBuffer.WriteByte(APDU_CONFIRMED_REQUEST | 0x02) // APDU Type (0x00) | PDU Flags (0x02)
	apduBuffer.WriteByte(0x75)                          // Max segments (7) | Max APDU (5)
	invokeID := GInvokeIDManager.Next()
	apduBuffer.WriteByte(invokeID) // Invoke ID
	apduBuffer.WriteByte(SERVICE_CONFIRMED_READ_PROPERTY_MULTIPLE)

	// Read Access Specification
	// Object Identifier
	apduBuffer.WriteByte(0x0C) // Tag 0, context-specific, length 4
	objectIdentifier := (uint32(object.Type) << 22) | object.Instance
	binary.Write(&apduBuffer, binary.BigEndian, objectIdentifier)

	// Opening tag for List of Property References
	apduBuffer.WriteByte(0x1E)

	// Property Reference
	apduBuffer.WriteByte(0x09) // Tag 0, context-specific, length 1
	apduBuffer.WriteByte(PROP_ALL)

	// Closing tag for List of Property References
	apduBuffer.WriteByte(0x1F)

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

	// Send ReadPropertyMultiple packet
	_, err := c.conn.WriteTo(buffer.Bytes(), &net.UDPAddr{IP: device.IPAddress, Port: device.Port})
	if err != nil {
		return nil, fmt.Errorf("failed to send ReadPropertyMultiple packet: %w", err)
	}

	// Listen for Complex-ACK response
	c.conn.SetReadDeadline(time.Now().Add(c.options.Timeout))
	readBuffer := make([]byte, 4096) // Increased buffer size for potentially large responses

	n, _, err := c.conn.ReadFromUDP(readBuffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("timeout waiting for ReadPropertyMultiple response")
		}
		return nil, fmt.Errorf("failed to read from UDP: %w", err)
	}

	return parseObjectPropertyList(readBuffer[:n], invokeID)
}

// ReadPropertiesFromMultipleObjects retrieves a specific property from multiple objects on a device.
func (c *BACnetClient) ReadPropertiesFromMultipleObjects(device DeviceInfo, objects []BACnetObject, propertyID uint32) (map[BACnetObject]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var apduBuffer bytes.Buffer

	// APDU (Confirmed-Request)
	apduBuffer.WriteByte(APDU_CONFIRMED_REQUEST | 0x02) // APDU Type (0x00) | PDU Flags (0x02)
	apduBuffer.WriteByte(0x75)                          // Max segments (7) | Max APDU (5)
	invokeID := GInvokeIDManager.Next()
	apduBuffer.WriteByte(SERVICE_CONFIRMED_READ_PROPERTY_MULTIPLE)

	// List of Read Access Specifications
	for _, obj := range objects {
		// Object Identifier
		apduBuffer.WriteByte(0x0C) // Tag 0, context-specific, length 4
		objectIdentifier := (uint32(obj.Type) << 22) | obj.Instance
		binary.Write(&apduBuffer, binary.BigEndian, objectIdentifier)

		// Opening tag for List of Property References
		apduBuffer.WriteByte(0x1E)

		// Property Reference
		apduBuffer.WriteByte(0x09) // Tag 0, context-specific, length 1
		binary.Write(&apduBuffer, binary.BigEndian, uint8(propertyID))

		// Closing tag for List of Property References
		apduBuffer.WriteByte(0x1F)
	}

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

	// Send ReadPropertyMultiple packet
	_, err := c.conn.WriteTo(buffer.Bytes(), &net.UDPAddr{IP: device.IPAddress, Port: device.Port})
	if err != nil {
		return nil, fmt.Errorf("failed to send ReadPropertyMultiple packet: %w", err)
	}

	// Listen for Complex-ACK response
	c.conn.SetReadDeadline(time.Now().Add(c.options.Timeout))
	readBuffer := make([]byte, 4096) // Increased buffer size for potentially large responses

	n, _, err := c.conn.ReadFromUDP(readBuffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("timeout waiting for ReadPropertyMultiple response")
		}
		return nil, fmt.Errorf("failed to read from UDP: %w", err)
	}

	return parseReadPropertyMultipleResponse(readBuffer[:n], invokeID)
}

// ReadSpecificPropertiesFromObject retrieves specific properties from a single object on a device.
func (c *BACnetClient) ReadSpecificPropertiesFromObject(device DeviceInfo, object BACnetObject, propertyIDs []uint32) (map[uint32]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var apduBuffer bytes.Buffer

	// APDU (Confirmed-Request)
	apduBuffer.WriteByte(APDU_CONFIRMED_REQUEST | 0x02) // APDU Type (0x00) | PDU Flags (0x02)
	apduBuffer.WriteByte(0x75)                          // Max segments (7) | Max APDU (5)
	invokeID := GInvokeIDManager.Next()
	apduBuffer.WriteByte(invokeID) // Invoke ID
	apduBuffer.WriteByte(SERVICE_CONFIRMED_READ_PROPERTY_MULTIPLE)

	// Read Access Specification for the single object
	// Object Identifier
	apduBuffer.WriteByte(0x0C) // Tag 0, context-specific, length 4
	objectIdentifier := (uint32(object.Type) << 22) | object.Instance
	binary.Write(&apduBuffer, binary.BigEndian, objectIdentifier)

	// Opening tag for List of Property References
	apduBuffer.WriteByte(0x1E)

	// Property References
	for _, propID := range propertyIDs {
		apduBuffer.WriteByte(0x09) // Tag 0, context-specific, length 1
		binary.Write(&apduBuffer, binary.BigEndian, uint8(propID))
	}

	// Closing tag for List of Property References
	apduBuffer.WriteByte(0x1F)

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

	// Send ReadPropertyMultiple packet
	_, err := c.conn.WriteTo(buffer.Bytes(), &net.UDPAddr{IP: device.IPAddress, Port: device.Port})
	if err != nil {
		return nil, fmt.Errorf("failed to send ReadPropertyMultiple packet: %w", err)
	}

	// Listen for Complex-ACK response
	c.conn.SetReadDeadline(time.Now().Add(c.options.Timeout))
	readBuffer := make([]byte, 4096) // Increased buffer size for potentially large responses

	n, _, err := c.conn.ReadFromUDP(readBuffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("timeout waiting for ReadPropertyMultiple response")
		}
		return nil, fmt.Errorf("failed to read from UDP: %w", err)
	}

	// Parse the response, expecting results for a single object
	parsedResults, err := parseReadPropertyMultipleResponse(readBuffer[:n], invokeID)
	if err != nil {
		return nil, err
	}

	// Extract properties for the requested object
	if singleObjectResults, ok := parsedResults[object]; ok {
		if propsMap, isMap := singleObjectResults.(map[uint32]interface{}); isMap {
			return propsMap, nil
		}
		return nil, fmt.Errorf("unexpected format for single object results")
	}

	return nil, fmt.Errorf("object %v not found in ReadPropertyMultiple response", object)
}

// parseReadPropertyMultipleResponse parses the response to a ReadPropertyMultiple request.
func parseReadPropertyMultipleResponse(data []byte, expectedInvokeID byte) (map[BACnetObject]interface{}, error) {
	r := bytes.NewReader(data)

	// BVLC & NPDU - skip
	var bvlcHeader BVLCHeader
	if err := binary.Read(r, binary.BigEndian, &bvlcHeader); err != nil {
		return nil, fmt.Errorf("error reading BVLC header: %w", err)
	}
	var npduHeader NPDU
	if err := binary.Read(r, binary.BigEndian, &npduHeader); err != nil {
		return nil, fmt.Errorf("error reading NPDU header: %w", err)
	}

	// APDU
	apduType, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading APDU type: %w", err)
	}
	if apduType&0xF0 == APDU_ERROR {
		return nil, fmt.Errorf("received BACnet Error PDU") // Basic error handling
	}
	if apduType&0xF0 != APDU_COMPLEX_ACK {
		return nil, fmt.Errorf("not a Complex-ACK, got 0x%x", apduType)
	}
	invokeID, _ := r.ReadByte()
	if invokeID != expectedInvokeID {
		return nil, fmt.Errorf("invoke ID mismatch: expected %d, got %d", expectedInvokeID, invokeID)
	}

	service, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading service choice: %w", err)
	}
	if service != SERVICE_CONFIRMED_READ_PROPERTY_MULTIPLE {
		return nil, fmt.Errorf("not a ReadPropertyMultiple ACK, got 0x%x", service)
	}

	results := make(map[BACnetObject]interface{})

	// The list of results continues until the APDU is fully read.
	for r.Len() > 0 {
		// It must be an object identifier.
		tag, err := r.ReadByte()
		if err != nil {
			break // Clean exit at end of data
		}
		if tag != 0x0C { // Context Tag 0, Length 4
			return nil, fmt.Errorf("expected object identifier tag 0x0C, got 0x%x", tag)
		}
		var objectIdentifier uint32
		if err := binary.Read(r, binary.BigEndian, &objectIdentifier); err != nil {
			return nil, fmt.Errorf("failed to read object identifier: %w", err)
		}
		currentObject := BACnetObject{
			Type:     ObjectType(objectIdentifier >> 22),
			Instance: objectIdentifier & 0x3FFFFF,
		}

		// Now comes the list of properties for this object.
		// Expect Context Tag 1, Opening Tag (0x1E)
		tag, err = r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read opening tag for property list: %w", err)
		}
		if tag != 0x1E {
			return nil, fmt.Errorf("expected opening tag 0x1E for property list, got 0x%x", tag)
		}

		// Properties for the current object
		objectProperties := make(map[uint32]interface{})
		for {
			tag, err := r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("failed to read tag inside property list: %w", err)
			}

			if tag == 0x1F { // Context Tag 1, Closing Tag
				break // End of properties for this object
			}

			if tag != 0x29 { // Context Tag 2, Length 1
				return nil, fmt.Errorf("expected property identifier tag 0x29, got 0x%x", tag)
			}
			var propID byte
			if err := binary.Read(r, binary.BigEndian, &propID); err != nil {
				return nil, fmt.Errorf("failed to read property identifier: %w", err)
			}

			// Expect Context Tag 4, Opening Tag (0x4E)
			tag, err = r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("failed to read opening tag for property value: %w", err)
			}
			if tag != 0x4E {
				return nil, fmt.Errorf("expected opening tag 0x4E for property value, got 0x%x", tag)
			}

			val, err := decodeApplicationValue(r)
			if err != nil {
				return nil, fmt.Errorf("failed to decode application value for prop %d: %w", propID, err)
			}

			// Expect Context Tag 4, Closing Tag (0x4F)
			tag, err = r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("failed to read closing tag for property value: %w", err)
			}
			if tag != 0x4F {
				return nil, fmt.Errorf("expected closing tag 0x4F for property value, got 0x%x", tag)
			}
			objectProperties[uint32(propID)] = val
		}
		results[currentObject] = objectProperties
	}

	return results, nil
}
