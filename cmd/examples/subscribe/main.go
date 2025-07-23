package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/maxzerker/bacnet"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s <interface> <device-id> <object-type> <object-instance>", os.Args[0])
	}

	ifaceName := os.Args[1]
	deviceID, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid device-id: %v", err)
	}
	objectType, err := strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatalf("Invalid object-type: %v", err)
	}
	objectInstance, err := strconv.Atoi(os.Args[4])
	if err != nil {
		log.Fatalf("Invalid object-instance: %v", err)
	}

	// Define the timeout for BACnet requests
	requestTimeout := 5 * time.Second

	// Find interface and broadcast address
	intf, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("could not find interface %s: %v", ifaceName, err)
	}

	addrs, err := intf.Addrs()
	if err != nil {
		log.Fatalf("could not get addresses for interface %s: %v", ifaceName, err)
	}

	var localAddr *net.UDPAddr
	var broadcastIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localAddr = &net.UDPAddr{IP: ipnet.IP, Port: bacnet.BACNET_DEFAULT_PORT}

				// Calculate broadcast IP
				ip := ipnet.IP.To4()
				mask := ipnet.Mask
				broadcastIP = make(net.IP, len(ip))
				for i := 0; i < len(ip); i++ {
					broadcastIP[i] = ip[i] | (^mask[i])
				}
				break
			}
		}
	}
	if localAddr == nil {
		log.Fatalf("could not find a suitable IPv4 address on interface %s", ifaceName)
	}

	broadcastAddr := &net.UDPAddr{
		IP:   broadcastIP,
		Port: bacnet.BACNET_DEFAULT_PORT,
	}

	// Create a new BACnet client
	clientOptions := bacnet.ClientOptions{
		LocalAddr: localAddr,
		Timeout:   requestTimeout,
	}
	client, err := bacnet.NewClient(clientOptions)
	if err != nil {
		log.Fatalf("Failed to create BACnet client: %v", err)
	}
	defer client.Close()

	// Discover devices on the network
	devices, err := bacnet.WhoIs(client.GetConn(), broadcastAddr, requestTimeout)
	if err != nil {
		log.Fatalf("WhoIs failed: %v", err)
	}

	var targetDevice bacnet.DeviceInfo
	found := false
	for _, device := range devices {
		if device.DeviceID == uint32(deviceID) {
			targetDevice = device
			found = true
			break
		}
	}

	if !found {
		log.Fatalf("Device with ID %d not found", deviceID)
	}

	fmt.Printf("Found device: %+v\n", targetDevice)

	// Subscribe to COV notifications
	object := bacnet.BACnetObject{
		Type:     bacnet.ObjectType(objectType),
		Instance: uint32(objectInstance),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	covChan, errChan := client.SubscribeCOV(ctx, targetDevice, object, 123, false, 60)

	fmt.Println("Subscribed to COV notifications. Waiting for updates...")

	for {
		select {
		case notification, ok := <-covChan:
			if !ok {
				fmt.Println("COV channel closed. Exiting.")
				return
			}
			fmt.Printf("Received COV Notification:\n")
			fmt.Printf("  Subscriber Process Identifier: %d\n", notification.SubscriberProcessIdentifier)
			initiatingDeviceTypeName, _ := bacnet.ObjectTypeNames[notification.InitiatingDeviceIdentifier.Type]
			fmt.Printf("  Initiating Device Identifier: %s:%d\n", initiatingDeviceTypeName, notification.InitiatingDeviceIdentifier.Instance)
			monitoredObjectTypeName, _ := bacnet.ObjectTypeNames[notification.MonitoredObjectIdentifier.Type]
			fmt.Printf("  Monitored Object Identifier: %s:%d\n", monitoredObjectTypeName, notification.MonitoredObjectIdentifier.Instance)
			fmt.Printf("  Time Remaining: %d seconds\n", notification.TimeRemaining)
			fmt.Printf("  List of Values:\n")
			for _, prop := range notification.ListOfValues {
				propName, ok := bacnet.PropertyNames[prop.PropertyID]
				if !ok {
					propName = "Unknown"
				}
				fmt.Printf("    %s (%d): %v\n", propName, prop.PropertyID, prop.Value)
			}
			fmt.Println("--------------------")
		case err, ok := <-errChan:
			if !ok {
				fmt.Println("Error channel closed. Exiting.")
				return
			}
			log.Fatalf("COV subscription error: %v", err)
		}
	}
}
