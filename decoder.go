package bacnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func decodeStatusFlags(r *bytes.Reader) (StatusFlags, error) {
	// Status_Flags is a BIT STRING with 4 bits:
	// bit 0: In Alarm
	// bit 1: Fault
	// bit 2: Overridden
	// bit 3: Out Of Service

	// The first byte of a BIT STRING indicates the number of unused bits in the last octet.
	// Since Status_Flags is always 4 bits, we expect 4 unused bits in the first byte.
	unusedBits, err := r.ReadByte()
	if err != nil {
		return StatusFlags{}, fmt.Errorf("failed to read unused bits for Status_Flags: %w", err)
	}

	if unusedBits != 4 {
		return StatusFlags{}, fmt.Errorf("unexpected number of unused bits for Status_Flags: %d", unusedBits)
	}

	flagsByte, err := r.ReadByte()
	if err != nil {
		return StatusFlags{}, fmt.Errorf("failed to read flags byte for Status_Flags: %w", err)
	}

	return StatusFlags{
		InAlarm:      (flagsByte>>3)&1 == 1,
		Fault:        (flagsByte>>2)&1 == 1,
		Overridden:   (flagsByte>>1)&1 == 1,
		OutOfService: (flagsByte>>0)&1 == 1,
	}, nil
}

func decodeApplicationValue(r *bytes.Reader) (interface{}, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	tagNumber := tag >> 4
	lenVal := uint32(tag & 0x0F)

	if lenVal == 5 {
		lenByte, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read extended length: %w", err)
		}
		lenVal = uint32(lenByte)
	}

	// A complete implementation would handle all BACnet application tags and extended lengths > 253
	switch tagNumber {
	case 0: // Null
		return nil, nil
	case 1: // Boolean
		return lenVal == 1, nil // len is the value for booleans
	case 2: // Unsigned Integer
		buf := make([]byte, lenVal)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		var val uint32
		for i := 0; i < int(lenVal); i++ {
			val = (val << 8) | uint32(buf[i])
		}
		return val, nil
	case 4: // Real
		var val float32
		if err := binary.Read(r, binary.BigEndian, &val); err != nil {
			return nil, err
		}
		return val, nil
	case 7: // CharacterString
		// First byte is the encoding
		_, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		buf := make([]byte, lenVal-1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf), nil
	case 8: // BitString (Status_Flags)
		flags, err := decodeStatusFlags(r)
		if err != nil {
			return nil, err
		}
		return flags, nil
	case 9: // Enumerated
		buf := make([]byte, lenVal)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		var val uint32
		for i := 0; i < int(lenVal); i++ {
			val = (val << 8) | uint32(buf[i])
		}
		return val, nil
	case 12: // ObjectIdentifier
		var val uint32
		if err := binary.Read(r, binary.BigEndian, &val); err != nil {
			return nil, err
		}
		return BACnetObject{Type: ObjectType(val >> 22), Instance: val & 0x3FFFFF}, nil
	default:
		buf := make([]byte, lenVal)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
}
