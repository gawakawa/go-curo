package main

import (
	"bytes"
	"fmt"
)

const (
	ICMP_TYPE_ECHO_REPLY   uint8 = 0
	ICMP_TYPE_ECHO_REQUEST uint8 = 8
)

type icmpHeader struct {
	icmpType uint8
	icmpCode uint8
	checksum uint16
}

type icmpEcho struct {
	identify  uint16
	sequence  uint16
	timestamp []uint8
	data      []uint8
}

type icmpDestinationUnreachable struct {
	unused uint32
	data   []uint8
}

type icmpTimeExceeded struct {
	unused uint32
	data   []uint8
}

type icmpMessage struct {
	icmpHeader                 icmpHeader
	icmpEcho                   icmpEcho
	icmpDestinationUnreachable icmpDestinationUnreachable
	icmpTimeExceeded           icmpTimeExceeded
}

// ECHO Reply メッセージを作成する
func (icmpmsg icmpMessage) ReplyPacket() (icmpPacket []byte) {
	var b bytes.Buffer

	// ICMP ヘッダ
	b.Write([]byte{ICMP_TYPE_ECHO_REPLY})
	b.Write([]byte{0x00})       // icmp code
	b.Write([]byte{0x00, 0x00}) // checksum

	// ICMP エコーメッセージ
	b.Write(uint16ToByte(icmpmsg.icmpEcho.identify))
	b.Write(uint16ToByte(icmpmsg.icmpEcho.sequence))
	b.Write(icmpmsg.icmpEcho.timestamp)
	b.Write(icmpmsg.icmpEcho.data)

	icmpPacket = b.Bytes()
	checksum := calcChecksum(icmpPacket)
	// 計算済のチェックサムをセット
	icmpPacket[2] = checksum[0]
	icmpPacket[3] = checksum[1]

	fmt.Printf("ICMP Packet to be sent is %x\n", icmpPacket)

	return icmpPacket
}

func icmpInput(inputdev *netDevice, sourceAddr, destAddr uint32, icmpPacket []byte) {
	// ICMP メッセージ長より短かったら何もしない
	if len(icmpPacket) < 4 {
		fmt.Println("Received too short ICMP Packet")
		return
	}

	// ICMP パケットとして解釈する
	icmpmsg := icmpMessage{
		icmpHeader: icmpHeader{
			icmpType: icmpPacket[0],
			icmpCode: icmpPacket[1],
			checksum: byteToUint16(icmpPacket[2:4]),
		},
		icmpEcho: icmpEcho{
			identify:  byteToUint16(icmpPacket[4:6]),
			sequence:  byteToUint16(icmpPacket[6:8]),
			timestamp: icmpPacket[8:16],
			data:      icmpPacket[16:],
		},
	}

	switch icmpmsg.icmpHeader.icmpType {
	case ICMP_TYPE_ECHO_REPLY:
		fmt.Println("ICMP ECHO REPLY is received")
	case ICMP_TYPE_ECHO_REQUEST:
		fmt.Println("ICMP ECHO REQUEST is received, Create Reply Packet")
		ipPacketEncapsulateOutput(inputdev, sourceAddr, destAddr, icmpmsg.ReplyPacket(), IP_PROTOCOL_NUM_ICMP)
	}
}
