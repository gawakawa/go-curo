package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

const IP_ADDRESS_LEN = 4
const IP_ADDRESS_LIMITED_BROADCAST uint32 = 0xffffffff
const IP_PROTOCOL_NUM_ICMP uint8 = 0x01
const IP_PROTOCOL_NUM_TCP uint8 = 0x06
const IP_PROTOCOL_NUM_UDP uint8 = 0x11

type ipDevice struct {
	address   uint32 // デバイスの IP アドレス
	netmask   uint32 // サブネットマスク
	broadcast uint32 // directed broadcast address: サブネット内の全ホストにブロードキャストするためのアドレス
	natdev    natDevice
}

type ipRouteType uint8

const (
	connected ipRouteType = iota
	network
)

type ipRouteEntry struct {
	iptype  ipRouteType
	netdev  *netDevice
	nexthop uint32
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

func (ipheader ipHeader) ToPacket(calc bool) (ipHeaderByte []byte) {
	var b bytes.Buffer

	b.Write([]byte{ipheader.version<<4 + ipheader.headerLen})
	b.Write([]byte{ipheader.tos})
	b.Write(uint16ToByte(ipheader.totalLen))
	b.Write(uint16ToByte(ipheader.identify))
	b.Write(uint16ToByte(ipheader.fragOffset))
	b.Write([]byte{ipheader.ttl})
	b.Write([]byte{ipheader.protocol})

	b.Write(uint16ToByte(ipheader.headerChecksum))
	b.Write(uint32ToByte(ipheader.srcAddr))
	b.Write(uint32ToByte(ipheader.destAddr))

	if calc {
		ipHeaderByte = b.Bytes()
		checksum := calcChecksum(ipHeaderByte)
		// 計算済のチェックサムをセット
		ipHeaderByte[10] = checksum[0]
		ipHeaderByte[11] = checksum[1]
	} else {
		ipHeaderByte = b.Bytes()
	}

	return ipHeaderByte
}

// サブネットマスクからプレフィックス長を計算する
func subnetToPrefixLen(netmask uint32) int {
	prefixLen := 0
	for netmask != 0 {
		prefixLen++
		netmask <<= 1
	}
	return prefixLen
}

func getIPdevice(addrs []net.Addr) (ipdev ipDevice) {
	for _, addr := range addrs {
		// IPv6 ではなく IPv4 アドレスをリターン
		ipaddrstr := addr.String()
		if !strings.Contains(ipaddrstr, ":") && strings.Contains(ipaddrstr, ".") {
			ip, ipnet, _ := net.ParseCIDR(ipaddrstr)
			ipdev.address = byteToUint32(ip.To4())
			ipdev.netmask = byteToUint32(ipnet.Mask)
			// directed broadcast address は、IP アドレスとサブネットマスクから計算できる
			ipdev.broadcast = ipdev.address | (^ipdev.netmask)
		}
	}
	return ipdev
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
		fmt.Printf("IP packet received from %s is too short\n", inputdev.name)
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
		fmt.Println("IP header options are not supported")
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

	var natPacket []byte
	// NAT の内側から外側への通信
	if inputdev.ipdev.natdev != (natDevice{}) {
		var err error
		switch ipheader.protocol {
		case IP_PROTOCOL_NUM_UDP:
			natPacket, err = natExec(&ipheader, natPacketHeader{packet: packet[20:]}, inputdev.ipdev.natdev, udp, outgoing)
			if err != nil {
				// NAT できないパケットはドロップ
				fmt.Printf("nat udp packet err is %s\n", err)
				return
			}
		case IP_PROTOCOL_NUM_TCP:
			natPacket, err = natExec(&ipheader, natPacketHeader{packet: packet[20:]}, inputdev.ipdev.natdev, tcp, outgoing)
			if err != nil {
				// NAT できないパケットはドロップ
				fmt.Printf("nat tcp packet err is %s\n", err)
				return
			}
		}
	}

	// 宛先 IP アドレスがルータの持っている IP アドレスでない場合はフォワーディングを行う
	route := iproute.radixTreeSearch(ipheader.destAddr)
	if route == (ipRouteEntry{}) {
		// 宛先までの経路が無かったらパケットを破棄する
		fmt.Printf("この IP への経路がありません : %s\n", printIPAddr(ipheader.destAddr))
		return
	}

	// TTL が 1 以下ならドロップ
	if ipheader.ttl <= 1 {
		// ICMP_TIME_EXCEEDED を実装
		return
	}

	ipheader.ttl--
	// TTL が変わったので IP ヘッダチェックサムを再計算する
	ipheader.headerChecksum = 0
	ipheader.headerChecksum = byteToUint16(calcChecksum(ipheader.ToPacket(true)))

	forwardPacket := ipheader.ToPacket(true)
	if inputdev.ipdev.natdev != (natDevice{}) { // NAT 変換後は送信元を置き換えて送信
		forwardPacket = append(forwardPacket, natPacket...)
	} else { // 元のペイロードをそのまま送信
		forwardPacket = append(forwardPacket, packet[20:]...)
	}

	switch route.iptype {
	// 直接接続ネットワークの経路なら host に直接送信
	case connected:
		ipPacketOutputToHost(route.netdev, ipheader.destAddr, forwardPacket)
	// 直接接続ネットワークの経路ではなかったら
	default:
		fmt.Printf("next hop is %s\n", printIPAddr(route.nexthop))
		fmt.Printf("forward packet is %x : %x\n", forwardPacket[0:20], natPacket)
		ipPacketOutputToNexthop(route.nexthop, forwardPacket)
	}
}

// 自分宛の IP パケットの処理
func ipInputToOurs(inputdev *netDevice, ipheader *ipHeader, packet []byte) {
	// NAT の外側から内側への通信か判断
	for _, dev := range netDeviceList {
		if dev.ipdev != (ipDevice{}) && dev.ipdev.natdev != (natDevice{}) && dev.ipdev.natdev.outsideIpAddr == ipheader.destAddr { // 送信先の IP が NAT の外側の IP なら
			// NAT の戻りのパケットを DNAT する
			natExecuted := false
			var destPacket []byte
			var err error
			switch ipheader.protocol {
			case IP_PROTOCOL_NUM_UDP:
				destPacket, err = natExec(ipheader, natPacketHeader{packet: packet}, dev.ipdev.natdev, udp, incoming)
				if err != nil {
					return
				}
				natExecuted = true
			case IP_PROTOCOL_NUM_TCP:
				destPacket, err = natExec(ipheader, natPacketHeader{packet: packet}, dev.ipdev.natdev, tcp, incoming)
				if err != nil {
					return
				}
				natExecuted = true
			}
			if natExecuted {
				ipPacket := ipheader.ToPacket(false)
				ipPacket = append(ipPacket, destPacket...)
				fmt.Printf("To dest is %s, checksum is %x, packet is %x\n", printIPAddr(ipheader.destAddr), ipheader.headerChecksum, ipPacket)
				ipPacketOutput(dev, iproute, ipheader.destAddr, ipPacket)
				return
			}
		}
	}

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
		fmt.Printf("Unhandled IP protocol number: %d\n", ipheader.protocol)
		return
	}
}

// 宛先 IP アドレスにパケットを送信する
func ipPacketOutputToHost(dev *netDevice, destAddr uint32, packet []byte) {
	// ARP テーブルを検索する
	destMacAddr, _ := searchArpTableEntry(destAddr)
	if destMacAddr == [6]uint8{0, 0, 0, 0, 0, 0} { // ARP エントリがなかったら
		fmt.Printf("Trying IP output to host, but no ARP record for %s\n", printIPAddr(destAddr))
		// ARP リクエストを送信
		sendArpRequest(dev, destAddr)
	} else { // ARP エントリがあったら
		// ARP テーブルから取得した MAC アドレスに向けてパケットをイーサネットでカプセル化して送信する
		ethernetOutput(dev, destMacAddr, packet, ETHER_TYPE_IP)
	}
}

// フォワードする IP アドレスにパケットを送信する
func ipPacketOutputToNexthop(nextHop uint32, packet []byte) {
	// ARP テーブルを検索する
	destMacAddr, dev := searchArpTableEntry(nextHop)
	if destMacAddr == [6]uint8{0, 0, 0, 0, 0, 0} { // ARP エントリがなかったら
		fmt.Printf("Trying IP output to nexthop, but no ARP record for %s\n", printIPAddr(nextHop))
		// ルーティングテーブルをルックアップする
		routeToNexthop := iproute.radixTreeSearch(nextHop)
		if routeToNexthop == (ipRouteEntry{}) || routeToNexthop.iptype != connected { // next hop に到達不能だったら
			fmt.Printf("Next hop %s is not reachable\n", printIPAddr(nextHop))
		} else { // 到達可能な nexthop が見つかったら
			// 見つかった nexthop の MAC アドレスを特定するために ARP リクエストを送信
			sendArpRequest(routeToNexthop.netdev, nextHop)
		}
	} else { // ARP エントリがあったら
		// ARP テーブルから取得した MAC アドレスに向けてパケットをイーサネットでカプセル化して送信する
		ethernetOutput(dev, destMacAddr, packet, ETHER_TYPE_IP)
	}
}

// IP パケットを送信する
func ipPacketOutput(outputdev *netDevice, routeTree radixTreeNode, destAddr uint32, packet []byte) {
	// 宛先 IP アドレスへの経路を探索
	route := routeTree.radixTreeSearch(destAddr)
	if route == (ipRouteEntry{}) { // 経路が見つからなかったら
		fmt.Printf("No route to %s\n", printIPAddr(destAddr))
	}

	switch route.iptype {
	// 直接接続されたネットワークだったら
	case connected:
		ipPacketOutputToHost(outputdev, destAddr, packet)
	// 直接つながっていないネットワークだったら
	case network:
		ipPacketOutputToNexthop(destAddr, packet)
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
