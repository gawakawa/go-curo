package main

/*
Network topology

+-------+      +----------+      +----------+      +-------+
| host1 |------| router1  |------| router2  |------| host2 |
+-------+      +----+-----+      +----------+      +-------+
 .1.2           .1.1 | .0.1        .0.2  .2.1        .2.2
                .3.1 |
                     +-----------+----------+      +-------+
                                 | router3  |------| host3 |
                                 +----------+      +-------+
                                  .3.2  .4.1        .4.2

IP Addresses:
  host1:   192.168.1.2  (gw: 192.168.1.1)
  router1: 192.168.1.1, 192.168.0.1, 192.168.3.1
  router2: 192.168.0.2, 192.168.2.1  (ip_forward=1)
  host2:   192.168.2.2  (gw: 192.168.2.1)
  router3: 192.168.3.2, 192.168.4.1  (ip_forward=1)
  host3:   192.168.4.2  (gw: 192.168.4.1)

go-curo runs in router1 namespace as a software router.
Routing table: 192.168.2.0/24 via 192.168.0.2 (router2)
*/

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

// ルーティングテーブル
var iproute radixTreeNode

var netDeviceList []*netDevice

func runChapter2(mode string) {
	const (
		router2IP    = 0xc0a80002 // 192.168.0.2
		host2Network = 0xc0a80200 // 192.168.2.0
	)

	// 直接接続ではない host2 へのルーティングを登録する
	routeEntryToHost2 := ipRouteEntry{
		iptype:  network,
		nexthop: router2IP,
	}
	// 192.168.2.0/24 の経路の登録
	iproute.radixTreeAdd(host2Network&0xffffff00, 24, routeEntryToHost2)

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

			// 直接接続ネットワークの経路をルートテーブルのエントリに設定
			routeEntry := ipRouteEntry{
				iptype: connected,
				netdev: &netdev,
			}
			prefixLen := subnetToPrefixLen(netdev.ipdev.netmask)
			iproute.radixTreeAdd(netdev.ipdev.address&netdev.ipdev.netmask, prefixLen, routeEntry)

			netDeviceList = append(netDeviceList, &netdev)
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
