package main

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
