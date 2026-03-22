package main

import "encoding/binary"

func byteToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func byteToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func uint16ToByte(i uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, i)
}

func uint32ToByte(i uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, i)
}
