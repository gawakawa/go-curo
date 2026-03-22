package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

var netDeviceList []*netDevice

func runChapter2(mode string) {
	// epoll 作成
	events := make([]syscall.EpollEvent, 10)
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		log.Fatalf("epoll create err: %s", err)
	}

	// ネットワークインターフェースの情報を取得する
	interfaces, _ := net.Interfaces()
	for _, netif := range interfaces {
		// 無視するインターフェースか確認する
		if !isIgnoreInterfaces(netif.Name) {
			// socket をオープン
			sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(syscall.ETH_P_ALL))
			if err != nil {
				log.Fatalf("create socket err: %s", err)
			}

			// socket にインターフェースを bind する
			addr := syscall.SockaddrLinklayer{
				Protocol: htons(syscall.ETH_P_ALL),
				Ifindex:  netif.Index,
			}
			err = syscall.Bind(sock, &addr)
			if err != nil {
				log.Fatalf("bind err: %s", err)
			}
			fmt.Printf("Created device %s socket %d address %s\n", netif.Name, sock, netif.HardwareAddr.String())

			// socket を epoll の監視対象として登録する
			err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, sock, &syscall.EpollEvent{
				Events: syscall.EPOLLIN,
				Fd:     int32(sock),
			})
			netaddrs, err := netif.Addrs()
			if err != nil {
				log.Fatalf("getting ip addr from nic interface is err: %s", err)
			}

			netdev := netDevice{
				name:     netif.Name,
				macaddr:  setMacAddr(netif.HardwareAddr),
				socket:   sock,
				sockaddr: addr,
				ipdev:    getIPdevice(netaddrs),
			}

			netDeviceList = append(netDeviceList, &netdev)
		}
	}

	for {
		// epoll_wait でパケットの受信を待つ
		nfds, err := syscall.EpollWait(epfd, events, -1)
		if err != nil {
			log.Fatalf("epoll wait err: %s", err)
		}
		for i := 0; i < nfds; i++ {
			// デバイスから通信を受信
			for _, netdev := range netDeviceList {
				// イベントがあったソケットとマッチしたらパケットを読み込む処理を実行する
				if events[i].Fd == int32(netdev.socket) {
					err := netdev.netDevicePoll(mode)
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}
	}
}
