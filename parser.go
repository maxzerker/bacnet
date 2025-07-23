package bacnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

func parseIAm(data []byte, addr net.UDPAddr) (DeviceInfo, error) {
	r := bytes.NewReader(data)

	// BVLC
	bvlcHeader := BVLCHeader{}
	if err := binary.Read(r, binary.BigEndian, &bvlcHeader); err != nil {
		return DeviceInfo{}, fmt.Errorf("error reading BVLC header: %w", err)
	}

	if bvlcHeader.Type != BVLC_TYPE_BACNET_IP {
		return DeviceInfo{}, fmt.Errorf("not a BACnet/IP packet")
	}

	// NPDU
	npduHeader := NPDU{}
	if err := binary.Read(r, binary.BigEndian, &npduHeader); err != nil {
		return DeviceInfo{}, fmt.Errorf("error reading NPDU header: %w", err)
	}

	// APDU
	apduHeader := APDUHeader{}
	apduType, _ := r.ReadByte()
	apduHeader.Type = apduType & 0xF0

	if apduHeader.Type != APDU_UNCONFIRMED_REQUEST {
		return DeviceInfo{}, fmt.Errorf("not an unconfirmed request, got %x", apduHeader.Type)
	}

	// Unconfirmed Service Choice
	serviceChoice, _ := r.ReadByte()
	if serviceChoice != SERVICE_UNCONFIRMED_I_AM {
		return DeviceInfo{}, fmt.Errorf("not an I-Am service, got %x", serviceChoice)
	}

	// I-Am Data (Object Identifier, Max APDU, Segmentation, Vendor ID)
	var objectIdentifier uint32
	var maxAPDULen uint16
	var segmentation uint8
	var vendorID uint16

	// Object Identifier
	// Expected tag: Application Tag 12 (BACnetObjectIdentifier), Length 4
	tag, err := r.ReadByte()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read object identifier tag: %w", err)
	}
	if tag != 0xC4 { // Application tag 12, length 4
		return DeviceInfo{}, fmt.Errorf("unexpected tag for object identifier: got 0x%x, expected 0xC4. Full packet: %x", tag, data)
	}
	if err := binary.Read(r, binary.BigEndian, &objectIdentifier); err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read object identifier: %w", err)
	}

	// Max APDU
	// Expected tag: Application Tag 2 (Unsigned), Length 2
	tag, err = r.ReadByte()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read max APDU tag: %w", err)
	}
	if tag != 0x22 { // Application tag 2, length 2
		return DeviceInfo{}, fmt.Errorf("unexpected tag for max APDU: got 0x%x, expected 0x22. Full packet: %x", tag, data)
	}
	if err := binary.Read(r, binary.BigEndian, &maxAPDULen); err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read max APDU: %w", err)
	}

	// Segmentation Supported
	// Expected tag: Application Tag 9 (Enumerated), Length 1
	tag, err = r.ReadByte()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read segmentation tag: %w", err)
	}
	if tag != 0x91 { // Application tag 9, length 1
		return DeviceInfo{}, fmt.Errorf("unexpected tag for segmentation: got 0x%x, expected 0x91. Full packet: %x", tag, data)
	}
	if err := binary.Read(r, binary.BigEndian, &segmentation); err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read segmentation: %w", err)
	}

	// Vendor ID
	// Expected tag: Application Tag 2 (Unsigned), Length 2
	tag, err = r.ReadByte()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read vendor ID tag: %w", err)
	}
	if tag != 0x22 { // Application tag 2, length 2
		return DeviceInfo{}, fmt.Errorf("unexpected tag for vendor ID: got 0x%x, expected 0x22. Full packet: %x", tag, data)
	}
	if err := binary.Read(r, binary.BigEndian, &vendorID); err != nil {
		return DeviceInfo{}, fmt.Errorf("failed to read vendor ID: %w", err)
	}

	return DeviceInfo{
		DeviceID:  objectIdentifier & 0x3FFFFF,
		IPAddress: addr.IP,
		Port:      addr.Port,
		MaxAPDU:   maxAPDULen,
	}, nil
}

func parseObjectList(data []byte, expectedInvokeID byte) ([]BACnetObject, error) {
	r := bytes.NewReader(data)
	var tag byte
	var err error

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
	if apduType&0xF0 != APDU_COMPLEX_ACK {
		return nil, fmt.Errorf("not a Complex-ACK, got %x", apduType)
	}
	invokeID, _ := r.ReadByte()
	if invokeID != expectedInvokeID {
		return nil, fmt.Errorf("invoke ID mismatch: expected %d, got %d", expectedInvokeID, invokeID)
	}

	service, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading service choice: %w", err)
	}
	if service != SERVICE_CONFIRMED_READ_PROPERTY {
		return nil, fmt.Errorf("not a ReadProperty ACK, got %x", service)
	}

	// Context Tag: Object Identifier
	tag, err = r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading object identifier tag: %w", err)
	}
	if tag != 0x0C { // Context 0, Length 4
		return nil, fmt.Errorf("expected object identifier tag 0x0C, got %x", tag)
	}
	var objID uint32
	if err := binary.Read(r, binary.BigEndian, &objID); err != nil {
		return nil, fmt.Errorf("error reading object identifier: %w", err)
	}

	// Context Tag: Property Identifier
	tag, err = r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading property identifier tag: %w", err)
	}
	if tag != 0x19 { // Context 1, Length 1
		return nil, fmt.Errorf("expected property identifier tag 0x19, got %x", tag)
	}
	var propID byte
	if err := binary.Read(r, binary.BigEndian, &propID); err != nil {
		return nil, fmt.Errorf("error reading property identifier: %w", err)
	}

	// Opening tag for the list of objects
	tag, err = r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading opening tag for object list: %w", err)
	}
	if tag != 0x3E { // Context-specific tag 3, opening tag
		return nil, fmt.Errorf("expected opening tag 0x3E for object list, got %x. Full packet: %x", tag, data)
	}

	var objectList []BACnetObject
	for {
		tag, err = r.ReadByte()
		if err != nil {
			break // EOF
		}

		if tag == 0x3F { // Context-specific tag 3, closing tag
			break
		}

		// It should be an object identifier, which is application-tagged.
		if tag == 0xC4 { // Application tag 12 (BACnetObjectIdentifier), length 4
			var rawObjId uint32
			if err := binary.Read(r, binary.BigEndian, &rawObjId); err != nil {
				return nil, fmt.Errorf("error reading object id from list: %w", err)
			}
			objectList = append(objectList, BACnetObject{
				Type:     ObjectType(rawObjId >> 22),
				Instance: rawObjId & 0x3FFFFF,
			})
		} else {
			return nil, fmt.Errorf("unexpected tag 0x%x in object list. Full packet: %x", tag, data)
		}
	}

	return objectList, nil
}

func parseObjectPropertyList(data []byte, expectedInvokeID byte) ([]BACnetPropertyValue, error) {
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

	var allProperties []BACnetPropertyValue

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

		// Now comes the list of properties for this object.
		// Expect Context Tag 1, Opening Tag (0x1E)
		tag, err = r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read opening tag for property list: %w", err)
		}
		if tag != 0x1E {
			return nil, fmt.Errorf("expected opening tag 0x1E for property list, got 0x%x", tag)
		}

		// Loop over each property result
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

			var values []interface{}
			for {
				peek, err := r.ReadByte()
				if err != nil {
					return nil, err
				}
				r.UnreadByte()

				if peek == 0x4F { // Context Tag 4, Closing Tag
					r.ReadByte() // consume it
					break
				}

				val, err := decodeApplicationValue(r)
				if err != nil {
					return nil, fmt.Errorf("failed to decode application value for prop %d: %w", propID, err)
				}
				values = append(values, val)
			}

			var finalValue interface{}
			if len(values) == 1 {
				finalValue = values[0]
			} else {
				finalValue = values
			}

			allProperties = append(allProperties, BACnetPropertyValue{
				PropertyID: uint32(propID),
				Value:      finalValue,
			})
		}
	}

	return allProperties, nil
}

func parseCOVNotification(data []byte) (COVNotification, error) {
	r := bytes.NewReader(data)

	// BVLC & NPDU - skip
	r.Seek(6, 0)

	// APDU
	apduType, err := r.ReadByte()
	if err != nil {
		return COVNotification{}, fmt.Errorf("error reading APDU type: %w", err)
	}
	if apduType&0xF0 != APDU_UNCONFIRMED_REQUEST {
		return COVNotification{}, fmt.Errorf("not an Unconfirmed-Request, got %x", apduType)
	}

	service, err := r.ReadByte()
	if err != nil {
		return COVNotification{}, fmt.Errorf("error reading service choice: %w", err)
	}
	var notification COVNotification

	if service != SERVICE_UNCONFIRMED_EVENT_NOTIFICATION {
		return COVNotification{}, fmt.Errorf("not a COV Notification or Event Notification, got %x", service)
	}

	// Subscriber Process Identifier
	tag, err := r.ReadByte()
	if tag != 0x09 { // Context 0, Length 1
		return COVNotification{}, fmt.Errorf("error reading subscriber process identifier tag: %w", err)
	}
	subId, _ := r.ReadByte()
	notification.SubscriberProcessIdentifier = uint32(subId)

	tag, err = r.ReadByte()
	// Initiating Device Identifier
	if tag != 0x1C { // Context tag 1, length 4
		return COVNotification{}, fmt.Errorf("unexpected tag for device identifier: got 0x%x, expected 0x1C.", tag)
	}

	var devId uint32
	binary.Read(r, binary.BigEndian, &devId)
	notification.InitiatingDeviceIdentifier = BACnetObject{Type: ObjectType(devId >> 22), Instance: devId & 0x3FFFFF}

	tag, err = r.ReadByte()
	// Monitored Object Identifier
	if tag != 0x2C { // Context tag 2, length 4
		return COVNotification{}, fmt.Errorf("unexpected tag for object identifier: got 0x%x, expected 0x2C.", tag)
	}

	var objId uint32
	binary.Read(r, binary.BigEndian, &objId)
	notification.MonitoredObjectIdentifier = BACnetObject{Type: ObjectType(objId >> 22), Instance: objId & 0x3FFFFF}

	// Time Remaining
	tag, err = r.ReadByte()
	if tag != 0x39 { // Context tag 3, length 1
		return COVNotification{}, fmt.Errorf("error reading time remaining tag: %w", err)
	}
	timeRem, _ := r.ReadByte()
	notification.TimeRemaining = uint32(timeRem)

	// List of Values (Context Tag 4, Opening Tag 0x4E) - This is common for both COV and Event Notifications
	tag, err = r.ReadByte()
	if err != nil {
		return COVNotification{}, fmt.Errorf("failed to read opening tag for property values: %w", err)
	}
	if tag != 0x4E { // Context Tag 4, Opening Tag
		return COVNotification{}, fmt.Errorf("expected opening tag 0x4E for property values, got 0x%x", tag)
	}

	for {
		tag, err := r.ReadByte()
		if err != nil {
			return COVNotification{}, fmt.Errorf("failed to read tag inside property values: %w", err)
		}

		if tag == 0x4F { // Context Tag 4, Closing Tag
			break
		}

		if tag != 0x09 { // Context Tag 0, Length 1
			return COVNotification{}, fmt.Errorf("expected property identifier tag 0x09, got 0x%x", tag)
		}
		var propID byte
		if err := binary.Read(r, binary.BigEndian, &propID); err != nil {
			return COVNotification{}, fmt.Errorf("failed to read property identifier: %w", err)
		}

		// Expect Context Tag 2, Opening Tag (0x2E)
		tag, err = r.ReadByte()
		if err != nil {
			return COVNotification{}, fmt.Errorf("failed to read opening tag for property value: %w", err)
		}
		if tag != 0x2E {
			return COVNotification{}, fmt.Errorf("expected opening tag 0x2E for property value, got 0x%x", tag)
		}

		val, err := decodeApplicationValue(r)
		if err != nil {
			return COVNotification{}, fmt.Errorf("failed to decode application value for prop %d: %w", propID, err)
		}

		// Expect Context Tag 2, Closing Tag (0x2F)
		tag, err = r.ReadByte()
		if err != nil {
			return COVNotification{}, fmt.Errorf("failed to read closing tag for property value: %w", err)
		}
		if tag != 0x2F {
			return COVNotification{}, fmt.Errorf("expected closing tag 0x2F for property value, got 0x%x", tag)
		}

		notification.ListOfValues = append(notification.ListOfValues, BACnetPropertyValue{
			PropertyID: uint32(propID),
			Value:      val,
		})
	}

	return notification, nil
}
