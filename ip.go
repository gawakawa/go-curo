package main

import "fmt"

const IP_ADDRESS_LEN = 4
const IP_ADDRESS_LIMITED_BROADCAST uint32 = 0xffffffff
const IP_PROTOCOL_NUM_ICMP uint8 = 0x01
const IP_PROTOCOL_NUM_TCP uint8 = 0x06
const IP_PROTOCOL_NUM_UDP uint8 = 0x11

type ipDevice struct {
	address   uint32 // デバイスの IP アドレス
	network   uint32 // サブネットマスク
	broadcast uint32 // ブロードキャストアドレス
}

type ipHeader struct {
	version        uint8  // バージョン
	headerLen      uint8  // ヘッダ長
	tos            uint8  // Type of Service パケットの優先度や転送方法を指定する
	totalLen       uint16 // トータルパケット長
	identify       uint16 // 識別番号
	fragOffset     uint16 // パケットの分割に関する情報
	ttl            uint8  // Time To Live
	protocol       uint8  // 上位プロトコルの番号
	headerChecksum uint16 // ヘッダのチェックサム
	srcAddr        uint32 // 送信元 IP アドレス
	destAddr       uint32 // 宛先 IP アドレス
}

func printIPAddr(ip uint32) string {
	ipbyte := uint32ToByte(ip)
	return fmt.Sprintf("%d.%d.%d.%d", ipbyte[0], ipbyte[1], ipbyte[2], ipbyte[3])
}

// IP パケットの受信処理
func ipInput(inputdev *netDevice, packet []byte) {
	// IP アドレスのついていないインターフェースからの受信は無視する
	if inputdev.ipdev.address == 0 {
		return
	}

	// パケットが IP ヘッダ長より短かったらドロップする
	if len(packet) < 20 {
		fmt.Printf("Received IP packet too short from %s\n", inputdev.name)
		return
	}

	// 受信した IP パケットをパースする
	ipheader := ipHeader{
		version:        packet[0] >> 4,
		headerLen:      packet[0] << 4 >> 4,
		tos:            packet[1],
		totalLen:       byteToUint16(packet[2:4]),
		identify:       byteToUint16(packet[4:6]),
		fragOffset:     byteToUint16(packet[6:8]),
		ttl:            packet[8],
		protocol:       packet[9],
		headerChecksum: byteToUint16(packet[10:12]),
		srcAddr:        byteToUint32(packet[12:16]),
		destAddr:       byteToUint32(packet[16:20]),
	}
	fmt.Printf("ipInput received IP in %s, packet type %d from %s to %s\n", inputdev.name, ipheader.protocol, printIPAddr(ipheader.srcAddr), printIPAddr(ipheader.destAddr))

	// 受信した MAC アドレスが ARP テーブルになければ追加しておく
	macaddr, _ := searchArpTableEntry(ipheader.srcAddr)
	if macaddr == [6]uint8{} {
		addArpTableEntry(inputdev, ipheader.srcAddr, inputdev.etheHeader.srcAddr)
	}

	// IPv4 でなければドロップ ( 本実装は IPv6 未対応 )
	if ipheader.version != 4 {
		if ipheader.version == 6 {
			fmt.Println("packet is IPv6")
		} else {
			fmt.Println("Incorrect IP version")
		}
		return
	}

	// IP ヘッダオプションがついていたらドロップする
	if 20 < (ipheader.headerLen * 4) {
		fmt.Println("IP header option is not supported")
		return
	}

	// 宛先アドレスがブロードキャストアドレスか、受信した NIC の IP アドレスの場合、自分宛の通信として処理する
	if ipheader.destAddr == IP_ADDRESS_LIMITED_BROADCAST || inputdev.ipdev.address == ipheader.destAddr {
		ipInputToOurs(inputdev, &ipheader, packet[20:])
		return
	}

	// 宛先 IP アドレスをルータが持っているか調べる
	// for _, dev := range netDeviceList {
	// 	// 宛先 IP アドレスが、ルータの持っている IP アドレス or ディレクテッド・ブロードキャストアドレスの場合
	// 	if dev.ipdev.address == ipheader.destAddr || dev.ipdev.broadcast == ipheader.destAddr {
	// 		ipInputToOurs(inputdev, &ipheader, packet[20:])
	// 		return
	// 	}
	// }
}

// 自分宛の IP パケットの処理
func ipInputToOurs(inputdev *netDevice, ipheader *ipHeader, packet []byte) {
	// 上位プロトコルの処理に移行
	switch ipheader.protocol {
	case IP_PROTOCOL_NUM_ICMP:
		fmt.Println("ICMP received")
	case IP_PROTOCOL_NUM_UDP:
		fmt.Printf("udp received: %x\n", packet)
	case IP_PROTOCOL_NUM_TCP:
		return
	default:
		fmt.Printf("Unhandled ip protocol number: %d\n", ipheader.protocol)
		return
	}

}
