package utils

import (
	"bytes"
	"encoding/binary"
	"io"
)

func BinaryDecoder(payload io.Reader, dests ...interface{}) error {
	for _, dest := range dests {
		err := binary.Read(payload, binary.BigEndian, dest)
		if err != nil {
			return err
		}
	}
	return nil
}

// ReadUint16FromBuffer reads Uint16 value from buffer and returns
// boolean flag telling if it was a success.
//
// Value is treated as big endian.
func ReadUint16FromBuffer(b *bytes.Buffer, x *uint16) bool {
	var buf [2]byte

	for i := range buf {
		bt, err := b.ReadByte()
		if err != nil {
			return false
		}
		buf[i] = bt
	}

	*x = binary.BigEndian.Uint16(buf[:])
	return true
}

// ReadUint32FromBuffer reads Uint32 value from buffer and returns
// boolean flag telling if it was a success.
//
// Value is treated as big endian.
func ReadUint32FromBuffer(b *bytes.Buffer, x *uint32) bool {
	var buf [4]byte

	for i := range buf {
		bt, err := b.ReadByte()
		if err != nil {
			return false
		}
		buf[i] = bt
	}

	*x = binary.BigEndian.Uint32(buf[:])
	return true
}
