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
	broadcast uint32 // directed broadcast address: サブネット内の全ホストにブロードキャストするためのアドレス
}

type ipHeader struct {
	version        uint8  // バージョン番号 (IPv4 なら 4)
	headerLen      uint8  // IP ヘッダの byte 数
	tos            uint8  // IP パケットの優先順位を指定する値
	totalLen       uint16 // トータルパケット長
	identify       uint16 // 個々のパケットを識別するための番号
	fragOffset     uint16 // パケットの分割に関する情報
	ttl            uint8  // パケットの生存時間
	protocol       uint8  // 上位プロトコルの番号
	headerChecksum uint16 // IP ヘッダのチェックサム
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

	// 宛先アドレスが limited broadcast address か、受信した NIC の IP アドレスの場合
	if ipheader.destAddr == IP_ADDRESS_LIMITED_BROADCAST || inputdev.ipdev.address == ipheader.destAddr {
		// 自分宛の通信として処理する
		ipInputToOurs(inputdev, &ipheader, packet[20:])
		return
	}

	// 宛先 IP アドレスをルータが持っているか調べる
	for _, dev := range netDeviceList {
		// 宛先 IP アドレスが、ルータの持っている IP アドレス or directed broadcast address の場合
		if dev.ipdev.address == ipheader.destAddr || dev.ipdev.broadcast == ipheader.destAddr {
			// 自分宛の通信として処理する
			ipInputToOurs(inputdev, &ipheader, packet[20:])
			return
		}
	}

	// TODO: フォワーディング処理を実装
}

// 自分宛の IP パケットの処理
func ipInputToOurs(inputdev *netDevice, ipheader *ipHeader, packet []byte) {
	// TODO: NAT を実装

	// 上位プロトコルの処理に移行
	switch ipheader.protocol {
	case IP_PROTOCOL_NUM_ICMP:
		fmt.Println("ICMP received")
		icmpInput(inputdev, ipheader.srcAddr, ipheader.destAddr, packet)
	case IP_PROTOCOL_NUM_UDP:
		fmt.Printf("udp received: %x\n", packet)
	case IP_PROTOCOL_NUM_TCP:
		return
	default:
		fmt.Printf("Unhandled ip protocol number: %d\n", ipheader.protocol)
		return
	}

}

// IP パケットを送信する
func ipPacketEncapsulateOutput(inputdev *netDevice, destAddr, srcAddr uint32, payload []byte, protocolType uint8) {
	var ipPacket []byte

	// IP ヘッダで必要な IP パケットの全長を算出する
	// ヘッダ長 (20 byte) + パケット長
	totalLength := 20 + len(payload)

	// IP ヘッダを構築
	ipheader := ipHeader{
		version:        4,
		headerLen:      20 / 4,
		tos:            0,
		totalLen:       uint16(totalLength),
		identify:       0xf80c,
		fragOffset:     2 << 13,
		ttl:            0x40,
		protocol:       protocolType,
		headerChecksum: 0, // 計算前は 0 をセットしておく
		srcAddr:        srcAddr,
		destAddr:       destAddr,
	}
	// IP ヘッダをパケットに追加する
	ipPacket = append(ipPacket, ipheader.ToPacket(true)...)
	// payload をパケットに追加する
	ipPacket = append(ipPacket, payload...)

	// ルートテーブルに送信先 IP アドレスの MAC アドレスがあるかを確認する
	destMacAddr, _ := searchArpTableEntry(destAddr)
	if destMacAddr != [6]uint8{0, 0, 0, 0, 0, 0} {
		// ルートテーブルに送信先 IP アドレスの MAC アドレスがあれば送信する
		ethernetOutput(inputdev, destMacAddr, ipPacket, ETHER_TYPE_IP)
	} else {
		// ルートテーブルに送信先 IP アドレスの MAC アドレスがなければ ARP リクエストを出す
		sendArpRequest(inputdev, destAddr)
	}
}
