package BasicStats

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/m-mizutani/tcpswarm/modules"
)

type frame struct {
	pktCount   int
	pktSize    int
	tcpCount   int
	tcpSize    int
	udpCount   int
	udpSize    int
	icmp4Count int
	icmp4Size  int
	icmp6Count int
	icmp6Size  int
	timestamp  time.Time
}

func newFrame() *frame {
	f := frame{
		timestamp: time.Now(),
	}
	return &f
}

// Handler is a packet processor of BasicStats
type Handler struct {
	frames []*frame
}

// Report is summary of BasicStats monitoring
type Report struct {
	frames []*frame
}

// New is a constructor of BasicStats handler
func New() modules.Handler {
	hdlr := Handler{
		frames: []*frame{newFrame()},
	}
	return &hdlr
}

// ReadPacket is a packet processor of BasicStats
func (x *Handler) ReadPacket(pkt *gopacket.Packet) {
	latest := x.frames[len(x.frames)-1]
	latest.pktCount++
	latest.pktSize += len((*pkt).Data())

	tpLayer := (*pkt).TransportLayer()
	if tpLayer == nil {
		return
	}

	switch tpLayer.LayerType() {
	case layers.LayerTypeTCP:
		latest.tcpCount++
		latest.tcpSize += latest.pktSize
	case layers.LayerTypeUDP:
		latest.udpCount++
		latest.udpSize += latest.pktSize
	case layers.LayerTypeICMPv4:
		latest.icmp4Count++
		latest.icmp4Size += latest.pktSize
	case layers.LayerTypeICMPv6:
		latest.icmp6Count++
		latest.icmp6Size += latest.pktSize
	}
}

func (x *Handler) MakeReport() modules.Report {
	const maxFrameNum = 10

	report := Report{}
	report.frames = x.frames
	x.frames = append(x.frames, newFrame())

	for len(x.frames) > maxFrameNum {
		x.frames = x.frames[1:]
	}

	return &report
}

// Title returns name of the report
func (x *Report) Title() string {
	return "Basic Stats"
}

// String to convert data to string
func (x *Report) String() string {
	f := x.frames[len(x.frames)-1]
	items := []string{
		fmt.Sprintf("pktCount=%d", f.pktCount),
		fmt.Sprintf("pktSize=%d", f.pktSize),
		fmt.Sprintf("tcpCount=%d", f.tcpCount),
		fmt.Sprintf("tcpSize=%d", f.tcpSize),
		fmt.Sprintf("udpCount=%d", f.udpCount),
		fmt.Sprintf("udpSize=%d", f.udpSize),
		fmt.Sprintf("icmp4Count=%d", f.icmp4Count),
		fmt.Sprintf("icmp4Size=%d", f.icmp4Size),
		fmt.Sprintf("icmp6Count=%d", f.icmp6Count),
		fmt.Sprintf("icmp6Size=%d", f.icmp6Size),
	}

	return strings.Join(items, "\t")
}

func (x *Report) Header() []string {
	return []string{
		"pktCount",
		"pktSize",
		"tcpCount",
		"tcpSize",
		"udpCount",
		"udpSize",
		"icmp4Count",
		"icmp4Size",
		"icmp6Count",
		"icmp6Size",
	}
}

// String to convert data to string
func (x *Report) Row() []string {
	f := x.frames[len(x.frames)-1]
	items := []string{
		fmt.Sprintf("%d", f.pktCount),
		fmt.Sprintf("%d", f.pktSize),
		fmt.Sprintf("%d", f.tcpCount),
		fmt.Sprintf("%d", f.tcpSize),
		fmt.Sprintf("%d", f.udpCount),
		fmt.Sprintf("%d", f.udpSize),
		fmt.Sprintf("%d", f.icmp4Count),
		fmt.Sprintf("%d", f.icmp4Size),
		fmt.Sprintf("%d", f.icmp6Count),
		fmt.Sprintf("%d", f.icmp6Size),
	}
	return items
}
