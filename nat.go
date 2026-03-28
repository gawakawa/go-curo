package main

import (
	"fmt"
)

type natDirectionType uint8

const (
	incoming natDirectionType = iota
	outgoing
)

type natProtocolType uint8

const (
	tcp natProtocolType = iota
	udp
	icmp
)

const (
	NAT_GLOBAL_PORT_MIN  = 20000
	NAT_GLOBAL_PORT_MAX  = 59999
	NAT_GLOBAL_PORT_SIZE = (NAT_GLOBAL_PORT_MAX - NAT_GLOBAL_PORT_MIN + 1)
)

type natPacketHeader struct {
	// TCP ヘッダか UDP ヘッダか ICMP
	packet []byte
}

type natEntry struct {
	globalIpAddr uint32
	localIpAddr  uint32
	globalPort   uint16
	localPort    uint16
}

// UDP, TCP の NAT テーブルのセット
type natEntryList struct {
	tcp []*natEntry
	udp []*natEntry
}

// NAT の内側の ip_device が持つ NAT デバイス
type natDevice struct {
	outsideIpAddr uint32
	natEntry      *natEntryList
}

func configureIPNat(inside string, outside uint32) {
	for _, dev := range netDeviceList {
		if inside == dev.name {
			dev.ipdev.natdev = natDevice{
				outsideIpAddr: outside,
				natEntry: &natEntryList{
					tcp: make([]*natEntry, NAT_GLOBAL_PORT_SIZE, NAT_GLOBAL_PORT_SIZE),
					udp: make([]*natEntry, NAT_GLOBAL_PORT_SIZE, NAT_GLOBAL_PORT_SIZE),
				},
			}
			fmt.Printf("Set nat to %s, outside ip addr is %s\n", inside, printIPAddr(outside))
		}
	}
}

// NAT エントリを作成する
func (entry *natEntryList) createNatEntry(protoType natProtocolType) *natEntry {
	switch protoType {
	case udp:
		for i, v := range entry.udp {
			// 空いているエントリが見つかったら、グローバルポートを設定してエントリを返す
			if v == nil {
				entry.udp[i] = &natEntry{
					globalPort: uint16(NAT_GLOBAL_PORT_MIN + i),
				}
				return entry.udp[i]
			}
		}
	case tcp:
		for i, v := range entry.tcp {
			// 空いているエントリが見つかったら、グローバルポートを設定してエントリを返す
			if v == nil {
				entry.tcp[i] = &natEntry{
					globalPort: uint16(NAT_GLOBAL_PORT_MIN + i),
				}
				return entry.tcp[i]
			}
		}
	}
	// 空いているエントリがなかったらゼロ値を返す
	return &natEntry{}
}

// グローバルアドレスとグローバルポートから NAT エントリを取得する
func (entry *natEntryList) getNatEntryByGlobal(protoType natProtocolType, ipaddr uint32, port uint16) *natEntry {
	fmt.Printf("getNatEntryByGlobal ipaddr is %s, port is %d\n", printIPAddr(ipaddr), port)
	switch protoType {
	case udp:
		for _, v := range entry.udp {
			if v != nil && v.globalIpAddr == ipaddr && v.globalPort == port {
				return v
			}
		}
	case tcp:
		for _, v := range entry.tcp {
			if v != nil && v.globalIpAddr == ipaddr && v.globalPort == port {
				return v
			}
		}
	}
	return &natEntry{}
}

// ローカルアドレスとローカルポートから NAT エントリを取得する
func (entry *natEntryList) getNatEntryByLocal(protoType natProtocolType, ipaddr uint32, port uint16) *natEntry {
	switch protoType {
	case udp:
		for _, v := range entry.udp {
			if v != nil && v.localIpAddr == ipaddr && v.localPort == port {
				return v
			}
		}
	case tcp:
		for _, v := range entry.tcp {
			if v != nil && v.localIpAddr == ipaddr && v.localPort == port {
				return v
			}
		}
	}
	return &natEntry{}
}

// NAT のアドレス変換を実行する
func natExec(ipheader *ipHeader, natPacket natPacketHeader, natdevice natDevice, proto natProtocolType, direction natDirectionType) ([]byte, error) {
	var udpheader udpHeader
	var tcpheader tcpHeader
	var srcPort, destPort uint16
	var packet []byte
	var checksum uint32
	var ipchecksum uint32

	// プロトコルに応じてパケットをパースする
	switch proto {
	case udp:
		udpheader = udpheader.ParsePacket(natPacket.packet)
		srcPort = udpheader.srcPort
		destPort = udpheader.destPort
	case tcp:
		tcpheader = tcpheader.ParsePacket(natPacket.packet)
		srcPort = tcpheader.srcPort
		destPort = tcpheader.destPort
	}

	var entry *natEntry
	if direction == incoming { // NAT の外から内への通信時
		// UDP と TCP のときはポート番号
		entry = natdevice.natEntry.getNatEntryByGlobal(proto, ipheader.destAddr, destPort)
		// NAT エントリがない場合はエラーを返す
		if entry == (&natEntry{}) {
			return nil, fmt.Errorf("No nat entry")
		}
		fmt.Printf("incoming nat from %s:%d to %s:%d\n", printIPAddr(entry.globalIpAddr), entry.globalPort, printIPAddr(entry.localIpAddr), entry.localPort)
		fmt.Printf("incoming ip header src is %s, dest is %s\n", printIPAddr(ipheader.srcAddr), printIPAddr(ipheader.destAddr))
		// IP ヘッダの送信先アドレスを entry のアドレスに置き換える
		ipheader.destAddr = entry.localIpAddr
		tcpheader.destPort = entry.localPort
	} else { // NAT の内から外への通信時
		entry = natdevice.natEntry.getNatEntryByLocal(proto, ipheader.srcAddr, srcPort)
		if entry.globalPort == 0 {
			// NAT エントリがなかったらエントリを作成する
			entry = natdevice.natEntry.createNatEntry(proto)
			if entry == (&natEntry{}) {
				return nil, fmt.Errorf("NAT table is full")
			}
			entry.globalIpAddr = natdevice.outsideIpAddr
			entry.localIpAddr = ipheader.srcAddr

			if proto == udp {
				entry.localPort = udpheader.srcPort
			} else {
				entry.localPort = tcpheader.srcPort
			}

			fmt.Printf("Now, nat entry local %s:%d to global %s:%d\n", printIPAddr(entry.localIpAddr), entry.localPort, printIPAddr(entry.globalIpAddr), entry.globalPort)
		}

		// IP ヘッダの送信元アドレスを外側のアドレスに変換する
		ipheader.srcAddr = entry.globalIpAddr
		tcpheader.srcPort = entry.globalPort
	}

	// チェックサムを NAT で書き換えたアドレスとポートの差分の分だけ再計算する
	if proto == udp {
		checksum = uint32(udpheader.checksum)
	} else {
		checksum = uint32(tcpheader.checksum)
	}
	// 反転前の 1 の補数和に戻す
	checksum = checksum ^ 0xffff
	ipchecksum = uint32(ipheader.headerChecksum ^ 0xffff)
	if direction == incoming {
		// 宛先 IP アドレスを引く
		checksum += (entry.localIpAddr - entry.globalIpAddr)
		checksum += uint32(entry.localPort - entry.globalPort)
		// 桁あふれした 1 の補数を足し込む
		checksum = (checksum & 0xffff) + checksum>>16
		ipchecksum += (entry.localIpAddr - entry.globalIpAddr)
		ipheader.headerChecksum = uint16(ipchecksum ^ 0xffff)
	} else {
		// 送信元の IP アドレスを引く
		checksum -= (entry.localIpAddr - entry.globalIpAddr)
		checksum -= uint32(entry.localPort - entry.globalPort)
		// 桁あふれした 1 の補数を足し込む
		checksum = (checksum & 0xffff) + checksum>>16
		ipchecksum -= (entry.localIpAddr - entry.globalIpAddr)
	}

	// 計算し直した checksum をパケットにつけ直す
	if proto == udp {
		udpheader.checksum = uint16(checksum ^ 0xffff)
		packet = udpheader.ToPacket()
	} else {
		tcpheader.checksum = uint16(checksum ^ 0xffff)
		packet = tcpheader.ToPacket()
	}

	return packet, nil
}
