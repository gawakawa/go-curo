package main

import "encoding/binary"

// checksum の補助関数
// バイト列を 2 バイトずつくっつけて 16bit 整数とし、それらを足し合わせる
func sumByteArr(packet []byte) uint {
	var sum uint
	n := len(packet)
	for i := 0; i < n-1; i += 2 {
		sum += uint(byteToUint16(packet[i:]))
	}
	if n%2 == 1 {
		sum += uint(packet[n-1]) << 8
	}
	return sum
}

// チェックサムを計算する
func calcChecksum(packet []byte) []byte {
	// まず、16 bit ごとに足す
	sum := sumByteArr(packet)
	// 16bit に収まるまで溢れた桁を足し戻す
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	// ビット反転した値を byte にして返す
	return uint16ToByte(uint16(^sum))
}

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
