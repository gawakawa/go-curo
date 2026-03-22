package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

func runChapter1() {
	var netDeviceList []netDevice
	events := make([]syscall.EpollEvent, 10)

	// epoll 作成
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		log.Fatalf("epoll create err: %s", err)
	}

	// ネットワークインタフェースの情報を取得する
	interfaces, _ := net.Interfaces()
	for _, netif := range interfaces {
		// パケットの処理対象のインタフェースかどうかを確認する
		if !isIgnoreInterfaces(netif.Name) {
			// socket を開く
			// AF_PACKET: 低レベルのパケットインターフェース
			// SOCK_RAW: 生のネットワークプロトコルへのアクセスを提供する
			sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
			if err != nil {
				log.Fatalf("create socket err: %s", err)
			}

			// socket にインタフェースを bind する
			addr := syscall.SockaddrLinklayer{
				Protocol: htons(syscall.ETH_P_ALL),
				Ifindex:  netif.Index,
			}
			err = syscall.Bind(sock, &addr)
			if err != nil {
				log.Fatalf("bind err: %s", err)
			}
			fmt.Printf("Created device %s socket %d addresses %s\n", netif.Name, sock, netif.HardwareAddr.String())

			// socket を epoll の監視対象として登録
			// EPOLLIN: 関連付けられたファイルに対して、read(2) 操作が可能である
			err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, sock, &syscall.EpollEvent{
				Events: syscall.EPOLLIN,
				Fd:     int32(sock),
			})
			if err != nil {
				log.Fatalf("epoll ctrl err: %s", err)
			}
			// ノンブロッキングに設定
			// err = syscall.SetNonblock(sock, true)
			// if err != nil {
			// 	log.Fatalf("set non block is err: %s", err)
			// }

			// netDevice 構造体を作成
			netDeviceList = append(netDeviceList, netDevice{
				name:     netif.Name,
				macaddr:  setMacAddr(netif.HardwareAddr),
				socket:   sock,
				sockaddr: addr,
			})
		}
	}

	for {
		// epoll_wait でパケットの受信を待つ
		nfds, err := syscall.EpollWait(epfd, events, -1)
		if err != nil {
			log.Fatalf("epoll wait err: %s", err)
		}
		for i := range nfds {
			// デバイスから通信を受信
			for _, netdev := range netDeviceList {
				// イベントが発生したソケットとマッチしたらパケットを読み込む処理を実行する
				if events[i].Fd == int32(netdev.socket) {
					err = netdev.netDevicePoll("ch1")
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}
	}
}
