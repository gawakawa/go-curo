package main

import (
	"fmt"
	"slices"
	"syscall"
)

type netDevice struct {
	name       string
	macaddr    [6]uint8
	socket     int
	sockaddr   syscall.SockaddrLinklayer
	etheHeader ethernetHeader
	ipdev      ipDevice // ルータの NW インターフェースにセットされた IP アドレスなどの情報を保持する
}

var IGNORE_INTERFACES = []string{
	"lo",
	"bond0",
	"dummy0",
	"tunl0",
	"sit0",
}

// ネットワークインターフェースがパケットの処理対象のものであるかを判別する
func isIgnoreInterfaces(name string) bool {
	return slices.Contains(IGNORE_INTERFACES, name)
}

// 16 ビット整数をホストのバイトオーダーからネットワークバイトオーダーに変換する
// ホストのエンディアンにかかわらずビッグエンディアンにする
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ネットデバイスの送信処理
func (netdev *netDevice) netDeviceTransmit(data []byte) error {
	// インターフェースに bind したソケットにパケットを送信する
	err := syscall.Sendto(netdev.socket, data, 0, &netdev.sockaddr)
	if err != nil {
		return err
	}
	return nil
}

// ネットデバイスの受信処理
func (netdev *netDevice) netDevicePoll(mode string) error {
	recvbuffer := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(netdev.socket, recvbuffer, 0)
	if err != nil {
		if n == -1 {
			return nil
		} else {
			return fmt.Errorf("recv err, n is %d, device is %s, err is %s", n, netdev.name, err)
		}
	}

	// Chapter1 では、受信したパケットを print するだけ
	if mode == "ch1" {
		fmt.Printf("Received %d bytes from %s: %x\n", n, netdev.name, recvbuffer[:n])
	} else {
		ethernetInput(netdev, recvbuffer[:n])
	}

	return nil
}

// インターフェース名からデバイスを探す
func getnetDeviceByName(name string) *netDevice {
	for _, dev := range netDeviceList {
		if name == dev.name {
			return dev
		}
	}
	return &netDevice{}
}
