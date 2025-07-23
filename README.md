## Disclaimer

This project is currently under active development and is not yet considered production-ready. The majority of the codebase has been generated with the assistance of AI. This code has been tested on HALO H3C Smarts Sensor Only.

# Go BACnet Library

This project provides an experimental BACnet library for Go. It addresses the common issue of unmaintained or non-functional BACnet implementations in the Go ecosystem, and while it "works(tm)" for my specific needs, it is not guaranteed to be robust for all use cases.

## Features

*   **BACnet IP Discovery:** Easily discover BACnet devices on your network.
*   **Object Property Reading:** Read specific properties from BACnet objects.
*   **Subscription to COV (Change of Value) Notifications:** Subscribe to real-time updates from BACnet devices.
*   **Extensible Architecture:** Designed to be easily extended for additional BACnet services.

## Getting Started

### Prerequisites

*   Go 1.18+

### Installation

To use this library in your Go project, simply run:

```bash
go get github.com/maxzerker/bacnet
```

### Usage

Here's a quick example of how to use the library for device discovery:

```go
// See cmd/examples/discover/main.go for a complete example
package main

import (
	"fmt"
	"github.com/maxzerker/bacnet"
	"time"
)

func main() {
	// Initialize BACnet client
	client, err := bacnet.NewClient("0.0.0.0:47808") // Listen on all interfaces, default BACnet port
	if err != nil {
		fmt.Println("Error creating client:", err)
		return
	}
	defer client.Close()

	// Discover devices
	devices, err := client.DiscoverDevices(5 * time.Second) // Discover for 5 seconds
	if err != nil {
		fmt.Println("Error discovering devices:", err)
		return
	}

	fmt.Println("Discovered Devices:")
	for _, dev := range devices {
		fmt.Printf("  Device ID: %d, Address: %s\n", dev.DeviceInstance, dev.Address)
	}
}
```

For more detailed examples, please refer to the `cmd/examples` directory:
*   `cmd/examples/discover`: Demonstrates BACnet device discovery.
*   `cmd/examples/readspecific`: Shows how to read specific object properties.
*   `cmd/examples/subscribe`: Illustrates subscribing to COV notifications.

## Project Structure

```
.
├── bacnet.go           // Core BACnet client and service implementations
├── constants.go        // BACnet constants and enumerations
├── decoder.go          // BACnet PDU decoding logic
├── go.mod              // Go module file
├── parser.go           // BACnet message parsing
├── request.go          // BACnet request building
├── subscribe.go        // COV subscription handling
└── cmd/
    └── examples/       // Example applications demonstrating library usage
        ├── discover/
        ├── readspecific/
        └── subscribe/
```

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue. For code contributions, please fork the repository and submit a pull request.

## License

This project is licensed under the GNU Lesser General Public License v3.0.