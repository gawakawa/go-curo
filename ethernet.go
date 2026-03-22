package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
)

const ETHER_TYPE_IP uint16 = 0x0800
const ETHER_TYPE_ARP uint16 = 0x0806
const ETHERNET_ADDRESS_LEN = 6 // MAC アドレスのバイト数

var ETHERNET_ADDRESS_BROADCAST = [6]uint8{
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
}

type ethernetHeader struct {
	destAddr  [6]uint8 // 宛先 MAC アドレス
	srcAddr   [6]uint8 // 送信元 MAC アドレス
	etherType uint16   // イーサタイプ
}

func (ethHeader ethernetHeader) ToPacket() []byte {
	var b bytes.Buffer

	b.Write(macToByte(ethHeader.destAddr))
	b.Write(macToByte(ethHeader.srcAddr))
	b.Write(uint16ToByte(ethHeader.etherType))

	return b.Bytes()
}

func printMacAddr(macaddr [6]uint8) string {
	var str string
	for _, v := range macaddr {
		str += fmt.Sprintf("%02x:", v)
	}
	return strings.TrimRight(str, ":")
}

func setMacAddr(macAddrByte []byte) [6]uint8 {
	return [6]uint8(macAddrByte)
}

func macToByte(macaddr [6]uint8) (b []byte) {
	return macaddr[:]
}

// イーサネットの受信処理
func ethernetInput(netdev *netDevice, packet []byte) {
	// 送られてきた通信をイーサネットフレームとして解釈する
	netdev.etheHeader.destAddr = setMacAddr(packet[0:6])
	netdev.etheHeader.srcAddr = setMacAddr(packet[6:12])
	netdev.etheHeader.etherType = byteToUint16(packet[12:14])

	// 自分の MAC アドレス宛かあるいはブロードキャストかを確認し、どちらでもなければ early return
	if netdev.macaddr != netdev.etheHeader.destAddr && netdev.etheHeader.destAddr != ETHERNET_ADDRESS_BROADCAST {
		return
	}

	// イーサタイプの値から上位プロトコルを特定する
	switch netdev.etheHeader.etherType {
	case ETHER_TYPE_ARP:
		arpInput(netdev, packet[14:])

	case ETHER_TYPE_IP:
		ipInput(netdev, packet[14:])
	}
}

/*
イーサネットでカプセル化して送信する
*/
func ethernetOutput(netdev *netDevice, destAddr [6]uint8, packet []byte, ethType uint16) {
	// イーサネットヘッダを持つパケットを作成する
	ethHeaderPacket := ethernetHeader{
		destAddr:  destAddr,
		srcAddr:   netdev.macaddr,
		etherType: ethType,
	}.ToPacket()

	// 送信するパケットをイーサネットヘッダにつなげる
	ethHeaderPacket = append(ethHeaderPacket, packet...)

	// ネットワークデバイスに送信する
	err := netdev.netDeviceTransmit(ethHeaderPacket)
	if err != nil {
		log.Fatalf("netDeviceTransmit is err: %v", err)
	}
}
