package bacnet

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// invokeIDManager provides thread-safe, unique Invoke IDs for BACnet requests.
type invokeIDManager struct {
	mu     sync.Mutex
	lastID byte
}

// Next returns the next available Invoke ID. It handles wrapping from 255 back to 0.
func (m *invokeIDManager) Next() byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastID++
	return m.lastID
}

// Global instance of the invoke ID manager.
var GInvokeIDManager = &invokeIDManager{}

type ObjectType uint32

const (
	OBJECT_ANALOG_INPUT       ObjectType = 0
	OBJECT_ANALOG_OUTPUT      ObjectType = 1
	OBJECT_ANALOG_VALUE       ObjectType = 2
	OBJECT_BINARY_INPUT       ObjectType = 3
	OBJECT_BINARY_OUTPUT      ObjectType = 4
	OBJECT_BINARY_VALUE       ObjectType = 5
	OBJECT_CALENDAR           ObjectType = 6
	OBJECT_COMMAND            ObjectType = 7
	OBJECT_DEVICE             ObjectType = 8
	OBJECT_EVENT_ENROLLMENT   ObjectType = 9
	OBJECT_FILE               ObjectType = 10
	OBJECT_GROUP              ObjectType = 11
	OBJECT_LOOP               ObjectType = 12
	OBJECT_MULTI_STATE_INPUT  ObjectType = 13
	OBJECT_MULTI_STATE_OUTPUT ObjectType = 14
	OBJECT_NOTIFICATION_CLASS ObjectType = 15
	OBJECT_PROGRAM            ObjectType = 16
	OBJECT_SCHEDULE           ObjectType = 17
	OBJECT_AVERAGING          ObjectType = 18
	OBJECT_MULTI_STATE_VALUE  ObjectType = 19
	OBJECT_TREND_LOG          ObjectType = 20
	OBJECT_LIFE_SAFETY_POINT  ObjectType = 21
	OBJECT_LIFE_SAFETY_ZONE   ObjectType = 22
	OBJECT_ACCUMULATOR        ObjectType = 23
	OBJECT_PULSE_CONVERTER    ObjectType = 24
)

var ObjectTypeNames = map[ObjectType]string{
	OBJECT_ANALOG_INPUT:       "AnalogInput",
	OBJECT_ANALOG_OUTPUT:      "AnalogOutput",
	OBJECT_ANALOG_VALUE:       "AnalogValue",
	OBJECT_BINARY_INPUT:       "BinaryInput",
	OBJECT_BINARY_OUTPUT:      "BinaryOutput",
	OBJECT_BINARY_VALUE:       "BinaryValue",
	OBJECT_CALENDAR:           "Calendar",
	OBJECT_COMMAND:            "Command",
	OBJECT_DEVICE:             "Device",
	OBJECT_EVENT_ENROLLMENT:   "EventEnrollment",
	OBJECT_FILE:               "File",
	OBJECT_GROUP:              "Group",
	OBJECT_LOOP:               "Loop",
	OBJECT_MULTI_STATE_INPUT:  "MultiStateInput",
	OBJECT_MULTI_STATE_OUTPUT: "MultiStateOutput",
	OBJECT_NOTIFICATION_CLASS: "NotificationClass",
	OBJECT_PROGRAM:            "Program",
	OBJECT_SCHEDULE:           "Schedule",
	OBJECT_AVERAGING:          "Averaging",
	OBJECT_MULTI_STATE_VALUE:  "MultiStateValue",
	OBJECT_TREND_LOG:          "TrendLog",
	OBJECT_LIFE_SAFETY_POINT:  "LifeSafetyPoint",
	OBJECT_LIFE_SAFETY_ZONE:   "LifeSafetyZone",
	OBJECT_ACCUMULATOR:        "Accumulator",
	OBJECT_PULSE_CONVERTER:    "PulseConverter",
}

var PropertyNames = map[uint32]string{
	uint32(PROP_ACKED_TRANSITIONS):               "AckedTransitions",
	uint32(PROP_ACK_REQUIRED):                    "AckRequired",
	uint32(PROP_ACTION):                          "Action",
	uint32(PROP_ACTION_TEXT):                     "ActionText",
	uint32(PROP_ACTIVE_TEXT):                     "ActiveText",
	uint32(PROP_ACTIVE_VT_SESSIONS):              "ActiveVtSessions",
	uint32(PROP_ALARM_VALUE):                     "AlarmValue",
	uint32(PROP_ALARM_VALUES):                    "AlarmValues",
	uint32(PROP_ALL):                             "All",
	uint32(PROP_ALL_WRITES_SUCCESSFUL):           "AllWritesSuccessful",
	uint32(PROP_APDU_SEGMENT_TIMEOUT):            "ApduSegmentTimeout",
	uint32(PROP_APDU_TIMEOUT):                    "ApduTimeout",
	uint32(PROP_APPLICATION_SOFTWARE_VERSION):    "ApplicationSoftwareVersion",
	uint32(PROP_ARCHIVE):                         "Archive",
	uint32(PROP_BIAS):                            "Bias",
	uint32(PROP_CHANGE_OF_STATE_COUNT):           "ChangeOfStateCount",
	uint32(PROP_CHANGE_OF_STATE_TIME):            "ChangeOfStateTime",
	uint32(PROP_NOTIFICATION_CLASS):              "NotificationClass",
	uint32(PROP_COV_INCREMENT):                   "CovIncrement",
	uint32(PROP_DATE_LIST):                       "DateList",
	uint32(PROP_DAYLIGHT_SAVINGS_STATUS):         "DaylightSavingsStatus",
	uint32(PROP_DEADBAND):                        "Deadband",
	uint32(PROP_DESCRIPTION):                     "Description",
	uint32(PROP_DEVICE_ADDRESS_BINDING):          "DeviceAddressBinding",
	uint32(PROP_DEVICE_TYPE):                     "DeviceType",
	uint32(PROP_EFFECTIVE_PERIOD):                "EffectivePeriod",
	uint32(PROP_ELAPSED_ACTIVE_TIME):             "ElapsedActiveTime",
	uint32(PROP_ERROR_LIMIT):                     "ErrorLimit",
	uint32(PROP_EVENT_ENABLE):                    "EventEnable",
	uint32(PROP_EVENT_STATE):                     "EventState",
	uint32(PROP_EVENT_TYPE):                      "EventType",
	uint32(PROP_EXCEPTION_SCHEDULE):              "ExceptionSchedule",
	uint32(PROP_FILE_ACCESS_METHOD):              "FileAccessMethod",
	uint32(PROP_FILE_SIZE):                       "FileSize",
	uint32(PROP_FILE_TYPE):                       "FileType",
	uint32(PROP_FIRMWARE_REVISION):               "FirmwareRevision",
	uint32(PROP_HIGH_LIMIT):                      "HighLimit",
	uint32(PROP_INSTANCE_OF):                     "InstanceOf",
	uint32(PROP_LIMIT_ENABLE):                    "LimitEnable",
	uint32(PROP_LIST_OF_GROUP_MEMBERS):           "ListOfGroupMembers",
	uint32(PROP_LIST_OF_OBJECT_PROPERTY_REFERENCES): "ListOfObjectPropertyReferences",
	uint32(PROP_OBJECT_IDENTIFIER):               "ObjectIdentifier",
	uint32(PROP_OBJECT_LIST):                     "ObjectList",
	uint32(PROP_OBJECT_NAME):                     "ObjectName",
	uint32(PROP_OBJECT_PROPERTY_REFERENCE):       "ObjectPropertyReference",
	uint32(PROP_OBJECT_TYPE):                     "ObjectType",
	uint32(PROP_OPTIONAL):                        "Optional",
	uint32(PROP_OUT_OF_SERVICE):                  "OutOfService",
	uint32(PROP_PRESENT_VALUE):                   "PresentValue",
	uint32(PROP_PRIORITY_ARRAY):                  "PriorityArray",
	uint32(PROP_PROFILE_NAME):                    "ProfileName",
	uint32(PROP_PROTOCOL_CONFORMANCE_CLASS):      "ProtocolConformanceClass",
	uint32(PROP_PROTOCOL_OBJECT_TYPES_SUPPORTED): "ProtocolObjectTypesSupported",
	uint32(PROP_PROTOCOL_SERVICES_SUPPORTED):     "ProtocolServicesSupported",
	uint32(PROP_PROTOCOL_VERSION):                "ProtocolVersion",
	uint32(PROP_RELIABILITY):                     "Reliability",
	uint32(PROP_REQUIRED):                        "Required",
	uint32(PROP_SEGMENTATION_SUPPORTED):          "SegmentationSupported",
	uint32(PROP_STATUS_FLAGS):                    "StatusFlags",
	uint32(PROP_SYSTEM_STATUS):                   "SystemStatus",
	uint32(PROP_UNITS):                           "Units",
	uint32(PROP_UPDATE_INTERVAL):                 "UpdateInterval",
	uint32(PROP_VENDOR_IDENTIFIER):               "VendorIdentifier",
	uint32(PROP_VENDOR_NAME):                     "VendorName",
}

type BACnetObject struct {
	Type     ObjectType
	Instance uint32
}

// StatusFlags represents the BACnet Status_Flags property.
type StatusFlags struct {
	InAlarm      bool
	Fault        bool
	Overridden   bool
	OutOfService bool
}

type BACnetPropertyValue struct {
	PropertyID uint32
	Value      interface{}
}

type COVNotification struct {
	SubscriberProcessIdentifier uint32
	InitiatingDeviceIdentifier  BACnetObject
	MonitoredObjectIdentifier   BACnetObject
	TimeRemaining               uint32
	ListOfValues                []BACnetPropertyValue
}

// BVLCHeader represents the BACnet/IP Virtual Link Control header.
type BVLCHeader struct {
	Type     byte
	Function byte
	Length   uint16
}

// NPDU represents the Network Protocol Data Unit.
type NPDU struct {
	Version byte
	Control byte
}

// APDU represents the Application Protocol Data Unit header.
type APDUHeader struct {
	Type    byte
	Service byte
}

// DeviceInfo represents a discovered BACnet device.
type DeviceInfo struct {
	DeviceID   uint32
	IPAddress  net.IP
	Port       int
	MacAddress []byte // BACnet MAC address (e.g., 0x08 for IP)
	MaxAPDU    uint16 // Max APDU length supported by the device
}

// ClientOptions holds configuration for a BACnetClient.
type ClientOptions struct {
	// LocalAddr is the local address to bind to. If nil, a suitable address is chosen.
	LocalAddr *net.UDPAddr
	// Timeout specifies the default timeout for BACnet requests.
	Timeout time.Duration
}

// BACnetClient manages network connections and configurations for BACnet interactions.
type BACnetClient struct {
	conn    *net.UDPConn
	options ClientOptions
	mu      sync.Mutex // Mutex to protect concurrent access to the connection
}

// NewClient creates and initializes a new BACnetClient.
func NewClient(options ClientOptions) (*BACnetClient, error) {
	conn, err := net.ListenUDP("udp4", options.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	return &BACnetClient{
		conn:    conn,
		options: options,
	}, nil
}

func (c *BACnetClient) Close() error {
	return c.conn.Close()
}

// GetConn returns the underlying UDP connection of the client.
func (c *BACnetClient) GetConn() *net.UDPConn {
	return c.conn
}
