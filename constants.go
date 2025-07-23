package bacnet

// BACnet constants
const (
	// BVLC (BACnet/IP Virtual Link Control)
	BVLC_TYPE_BACNET_IP byte = 0x81

	// BVLC Functions
	BVLC_RESULT                            byte = 0x00
	BVLC_WRITE_BROADCAST_DIST_TABLE        byte = 0x01
	BVLC_READ_BROADCAST_DIST_TABLE         byte = 0x02
	BVLC_READ_BROADCAST_DIST_TABLE_ACK     byte = 0x03
	BVLC_FORWARDED_NPDU                    byte = 0x04
	BVLC_REGISTER_FOREIGN_DEVICE           byte = 0x05
	BVLC_READ_FOREIGN_DEVICE_TABLE         byte = 0x06
	BVLC_READ_FOREIGN_DEVICE_TABLE_ACK     byte = 0x07
	BVLC_DELETE_FOREIGN_DEVICE_TABLE_ENTRY byte = 0x08
	BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK   byte = 0x09
	BVLC_ORIGINAL_UNICAST_NPDU             byte = 0x0a
	BVLC_ORIGINAL_BROADCAST_NPDU           byte = 0x0b

	// NPDU (Network Protocol Data Unit) Control Field
	NPDU_CONTROL_NORMAL_MESSAGE        byte = 0x00
	NPDU_CONTROL_URGENT_MESSAGE        byte = 0x04
	NPDU_CONTROL_EXPECTING_REPLY       byte = 0x08
	NPDU_CONTROL_NETWORK_LAYER_MESSAGE byte = 0x80

	// APDU (Application Protocol Data Unit) Types
	APDU_CONFIRMED_REQUEST   byte = 0x00
	APDU_UNCONFIRMED_REQUEST byte = 0x10
	APDU_SIMPLE_ACK          byte = 0x20
	APDU_COMPLEX_ACK         byte = 0x30
	APDU_SEGMENT_ACK         byte = 0x40
	APDU_ERROR               byte = 0x50
	APDU_REJECT              byte = 0x60
	APDU_ABORT               byte = 0x70

	// Unconfirmed Service Choice
	SERVICE_UNCONFIRMED_I_AM             byte = 0x00
	SERVICE_UNCONFIRMED_WHO_IS           byte = 0x08
	SERVICE_UNCONFIRMED_COV_NOTIFICATION byte = 0x01
	SERVICE_UNCONFIRMED_EVENT_NOTIFICATION byte = 0x02

	// Confirmed Service Choice
	SERVICE_CONFIRMED_READ_PROPERTY          byte = 0x0c
	SERVICE_CONFIRMED_READ_PROPERTY_MULTIPLE byte = 0x0e
	SERVICE_CONFIRMED_SUBSCRIBE_COV          byte = 0x05

	// Property IDs
	PROP_ACKED_TRANSITIONS                  byte = 0
	PROP_ACK_REQUIRED                       byte = 1
	PROP_ACTION                             byte = 2
	PROP_ACTION_TEXT                        byte = 3
	PROP_ACTIVE_TEXT                        byte = 4
	PROP_ACTIVE_VT_SESSIONS                 byte = 5
	PROP_ALARM_VALUE                        byte = 6
	PROP_ALARM_VALUES                       byte = 7
	PROP_ALL                                byte = 8
	PROP_ALL_WRITES_SUCCESSFUL              byte = 9
	PROP_APDU_SEGMENT_TIMEOUT               byte = 10
	PROP_APDU_TIMEOUT                       byte = 11
	PROP_APPLICATION_SOFTWARE_VERSION       byte = 12
	PROP_ARCHIVE                            byte = 13
	PROP_BIAS                               byte = 14
	PROP_CHANGE_OF_STATE_COUNT              byte = 15
	PROP_CHANGE_OF_STATE_TIME               byte = 16
	PROP_NOTIFICATION_CLASS                 byte = 17
	PROP_COV_INCREMENT                      byte = 22
	PROP_DATE_LIST                          byte = 23
	PROP_DAYLIGHT_SAVINGS_STATUS            byte = 24
	PROP_DEADBAND                           byte = 25
	PROP_DESCRIPTION                        byte = 28
	PROP_DEVICE_ADDRESS_BINDING             byte = 30
	PROP_DEVICE_TYPE                        byte = 31
	PROP_EFFECTIVE_PERIOD                   byte = 32
	PROP_ELAPSED_ACTIVE_TIME                byte = 33
	PROP_ERROR_LIMIT                        byte = 34
	PROP_EVENT_ENABLE                       byte = 35
	PROP_EVENT_STATE                        byte = 36
	PROP_EVENT_TYPE                         byte = 37
	PROP_EXCEPTION_SCHEDULE                 byte = 38
	PROP_FILE_ACCESS_METHOD                 byte = 41
	PROP_FILE_SIZE                          byte = 42
	PROP_FILE_TYPE                          byte = 43
	PROP_FIRMWARE_REVISION                  byte = 44
	PROP_HIGH_LIMIT                         byte = 45
	PROP_INSTANCE_OF                        byte = 48
	PROP_LIMIT_ENABLE                       byte = 52
	PROP_LIST_OF_GROUP_MEMBERS              byte = 53
	PROP_LIST_OF_OBJECT_PROPERTY_REFERENCES byte = 54
	PROP_OBJECT_IDENTIFIER                  byte = 75
	PROP_OBJECT_LIST                        byte = 76
	PROP_OBJECT_NAME                        byte = 77
	PROP_OBJECT_PROPERTY_REFERENCE          byte = 78
	PROP_OBJECT_TYPE                        byte = 79
	PROP_OPTIONAL                           byte = 80
	PROP_OUT_OF_SERVICE                     byte = 81
	PROP_PRESENT_VALUE                      byte = 85
	PROP_PRIORITY_ARRAY                     byte = 87
	PROP_PROFILE_NAME                       byte = 90
	PROP_PROTOCOL_CONFORMANCE_CLASS         byte = 92
	PROP_PROTOCOL_OBJECT_TYPES_SUPPORTED    byte = 97
	PROP_PROTOCOL_SERVICES_SUPPORTED        byte = 98
	PROP_PROTOCOL_VERSION                   byte = 100
	PROP_RELIABILITY                        byte = 103
	PROP_REQUIRED                           byte = 104
	PROP_SEGMENTATION_SUPPORTED             byte = 107
	PROP_STATUS_FLAGS                       byte = 111
	PROP_SYSTEM_STATUS                      byte = 112
	PROP_UNITS                              byte = 117
	PROP_UPDATE_INTERVAL                    byte = 118
	PROP_VENDOR_IDENTIFIER                  byte = 120
	PROP_VENDOR_NAME                        byte = 121

	BACNET_DEFAULT_PORT = 47808
)