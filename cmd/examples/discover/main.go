package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/maxzerker/bacnet"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <interface>", os.Args[0])
	}
	ifaceName := os.Args[1]

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
	fmt.Println("Performing Who-Is broadcast...")
	devices, err := bacnet.WhoIs(client.GetConn(), broadcastAddr, requestTimeout)
	if err != nil {
		log.Fatalf("WhoIs failed: %v", err)
	}

	if len(devices) == 0 {
		fmt.Println("No devices found.")
		return
	}

	fmt.Printf("Discovered %d device(s):\n", len(devices))
	for _, device := range devices {
		fmt.Printf("----------------------------------------\n")
		fmt.Printf("Device ID: %d\n", device.DeviceID)
		fmt.Printf("IP Address: %s, Port: %d\n", device.IPAddress, device.Port)
		// Get the object list for the device
		fmt.Println("  Getting object list...")
		objectList, err := client.GetObjectList(device)
		if err != nil {
			log.Printf("  Failed to get object list for device %d: %v", device.DeviceID, err)
			continue
		}

		fmt.Printf("  Found %d object(s):\n", len(objectList))
		for _, object := range objectList {
			objectTypeName, ok := bacnet.ObjectTypeNames[object.Type]
			if !ok {
				objectTypeName = "Unknown"
			}
			fmt.Printf("    - Object: %s, Instance: %d\n", objectTypeName, object.Instance)

			// Get all properties for the object
			properties, err := client.GetObjectAllPropertyList(device, object)
			if err != nil {
				log.Printf("      Failed to get properties for object %s:%d: %v", objectTypeName, object.Instance, err)
				continue
			}

			for _, prop := range properties {
				propName, ok := bacnet.PropertyNames[prop.PropertyID]
				if !ok {
					propName = "Unknown"
				}
				fmt.Printf("      - %s (%d): %v\n", propName, prop.PropertyID, prop.Value)
			}
		}
	}
	fmt.Printf("----------------------------------------\n")
}
