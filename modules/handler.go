package modules

import "github.com/google/gopacket"

// Report is interface of monitoring summary
type Report interface {
	Title() string
	String() string
	Header() []string
	Row() []string
}

// Handler is a function to summarize packets
type Handler interface {
	ReadPacket(pkt *gopacket.Packet)
	MakeReport() Report
}
