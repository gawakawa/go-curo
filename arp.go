package main

import (
	"bytes"
	"fmt"
)

const ARP_OPERATION_CODE_REQUEST = 1
const ARP_OPERATION_CODE_REPLY = 2
const ARP_HTYPE_ETHERNET uint16 = 0001 // ETHERNET の hardware type

// ARP テーブル
var ArpTableEntryList []*arpTableEntry

type arpTableEntry struct {
	macAddr [6]uint8
	ipAddr  uint32
	netdev  *netDevice
}

type arpIPToEthernet struct {
	hardwareType       uint16   // ハードウェアタイプ
	protocolType       uint16   // プロトコルタイプ
	hardwareLen        uint8    // ハードウェアアドレス長
	protocolLen        uint8    // プロトコルアドレス長
	opcode             uint16   // オペレーションコード
	senderHardwareAddr [6]uint8 // 送信元 MAC アドレス
	senderIPAddr       uint32   // 送信者の IP アドレス
	targetHardwareAddr [6]uint8 // ターゲットの MAC アドレス
	targetIPAddr       uint32   // ターゲットの IP アドレス
}

func (arpmsg arpIPToEthernet) ToPacket() []byte {
	var b bytes.Buffer

	b.Write(uint16ToByte(arpmsg.hardwareType))
	b.Write(uint16ToByte(arpmsg.protocolType))
	b.Write([]byte{arpmsg.hardwareLen})
	b.Write([]byte{arpmsg.protocolLen})
	b.Write(uint16ToByte(arpmsg.opcode))
	b.Write(macToByte(arpmsg.senderHardwareAddr))
	b.Write(uint32ToByte(uint32(arpmsg.senderIPAddr)))
	b.Write(macToByte(arpmsg.targetHardwareAddr))
	b.Write(uint32ToByte(arpmsg.targetIPAddr))

	return b.Bytes()
}

// ARP テーブルエントリの追加・更新
func addArpTableEntry(netdev *netDevice, ipaddr uint32, macaddr [6]uint8) {
	// 既存の ARP テーブルの更新が必要かどうか確かめる
	if len(ArpTableEntryList) != 0 {
		for _, arpTable := range ArpTableEntryList {
			// IP アドレスは同じだが Mac アドレスが異なる場合は更新する
			if arpTable.ipAddr == ipaddr && arpTable.macAddr != macaddr {
				arpTable.macAddr = macaddr
			}
			// Mac アドレスは同じだが IP アドレスが異なる場合は更新する
			if arpTable.macAddr == macaddr && arpTable.ipAddr != ipaddr {
				arpTable.ipAddr = ipaddr
			}
			// IP アドレスと Mac アドレスが全く同じエントリがすでに存在する場合は何もせず終了
			if arpTable.macAddr == macaddr && arpTable.ipAddr == ipaddr {
				return
			}
		}
	}

	// 一致するエントリがなかった場合は新規追加する
	ArpTableEntryList = append(ArpTableEntryList, &arpTableEntry{
		macAddr: macaddr,
		ipAddr:  ipaddr,
		netdev:  netdev,
	})
}

/*
ARP パケットの受信処理
*/
func arpInput(netdev *netDevice, packet []byte) {
	// ARP パケットの規定より短かったら early return
	if len(packet) < 28 {
		fmt.Printf("received too short ARP packet")
		return
	}

	// パケットをパースする
	arpMsg := arpIPToEthernet{
		hardwareType:       byteToUint16(packet[0:2]),
		protocolType:       byteToUint16(packet[2:4]),
		hardwareLen:        packet[4],
		protocolLen:        packet[5],
		opcode:             byteToUint16(packet[6:8]),
		senderHardwareAddr: setMacAddr(packet[8:14]),
		senderIPAddr:       byteToUint32(packet[14:18]),
		targetHardwareAddr: setMacAddr(packet[18:24]),
		targetIPAddr:       byteToUint32(packet[24:28]),
	}

	switch arpMsg.protocolType {
	case ETHER_TYPE_IP:
		if arpMsg.hardwareLen != ETHERNET_ADDRESS_LEN {
			fmt.Println("Illegal hardware address length")
			return
		}

		if arpMsg.protocolLen != IP_ADDRESS_LEN {
			fmt.Println("Illegal protocol address length")
			return
		}

		// オペレーションコードによって分岐
		if arpMsg.opcode == ARP_OPERATION_CODE_REQUEST {
			// ARP リクエストの受信
			fmt.Printf("ARP Request Packet is %+v\n", arpMsg)
			arpRequestArrives(netdev, arpMsg)
		} else {
			// ARP リプライの受信
			fmt.Printf("ARP Reply Packet is %+v\n", arpMsg)
			arpReplyArrives(netdev, arpMsg)
		}
	}
}

/*
ARP リクエストパケットの受信処理
*/
func arpRequestArrives(netdev *netDevice, arp arpIPToEthernet) {
	// IP アドレスが設定されているデバイスからの受信で、かつ要求されているアドレスが自分のものだったら応答する
	if netdev.ipdev.address != 00000000 && netdev.ipdev.address == arp.targetIPAddr {
		fmt.Printf("Sending arp reply to %s\n", printIPAddr(arp.targetIPAddr))
		// ARP リプライのパケットを作成
		arpPacket := arpIPToEthernet{
			hardwareType:       ARP_HTYPE_ETHERNET,
			protocolType:       ETHER_TYPE_IP,
			hardwareLen:        ETHERNET_ADDRESS_LEN,
			protocolLen:        IP_ADDRESS_LEN,
			opcode:             ARP_OPERATION_CODE_REPLY,
			senderHardwareAddr: netdev.macaddr,
			senderIPAddr:       netdev.ipdev.address,
			targetHardwareAddr: arp.senderHardwareAddr,
			targetIPAddr:       arp.senderIPAddr,
		}.ToPacket()

		// イーサネットでカプセル化して送信
		ethernetOutput(netdev, arp.senderHardwareAddr, arpPacket, ETHER_TYPE_ARP)
	}
}

// ARP テーブルの検索
func searchArpTableEntry(ipaddr uint32) ([6]uint8, *netDevice) {
	if len(ArpTableEntryList) != 0 {
		for _, arpTable := range ArpTableEntryList {
			if arpTable.ipAddr == ipaddr {
				return arpTable.macAddr, arpTable.netdev
			}
		}
	}
	return [6]uint8{}, nil
}

// ARP リプライパケットの受信処理
func arpReplyArrives(netdev *netDevice, arp arpIPToEthernet) {
	// IP アドレスが設定されているデバイスからの受信だったときのみ受理する
	if netdev.ipdev.address != 00000000 {
		fmt.Printf("Added arp table entry by arp reply (%s => %s)\n", printIPAddr(arp.senderIPAddr), printMacAddr(arp.senderHardwareAddr))
		// ARP テーブルエントリを追加する
		addArpTableEntry(netdev, arp.senderIPAddr, arp.senderHardwareAddr)
	}
}

// ARP リクエストを送信する
func sendArpRequest(netdev *netDevice, targetip uint32) {
	fmt.Printf("Sending arp request via %s for %x\n", netdev.name, targetip)
	// ARP リクエストのパケットを作成する
	arpPacket := arpIPToEthernet{
		hardwareType:       ARP_HTYPE_ETHERNET,
		protocolType:       ETHER_TYPE_IP,
		hardwareLen:        ETHERNET_ADDRESS_LEN,
		protocolLen:        IP_ADDRESS_LEN,
		opcode:             ARP_OPERATION_CODE_REQUEST,
		senderHardwareAddr: netdev.macaddr,
		senderIPAddr:       netdev.ipdev.address,
		targetHardwareAddr: ETHERNET_ADDRESS_BROADCAST,
		targetIPAddr:       targetip,
	}.ToPacket()
	// ethernet でカプセル化して送信
	ethernetOutput(netdev, ETHERNET_ADDRESS_BROADCAST, arpPacket, ETHER_TYPE_ARP)
}
