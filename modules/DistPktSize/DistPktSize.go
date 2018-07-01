package DistPktSize

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/m-mizutani/tcpswarm/modules"
)

type distMap []int

var distUnit = []int{90, 200, 500, 1000, 1500}

func newDistMap() distMap {
	return make(distMap, len(distUnit)+1)
}

func (x *distMap) count(pktSize int) {
	for idx, upper := range distUnit {
		if pktSize <= upper {
			(*x)[idx]++
			return
		}
	}

	(*x)[len(distUnit)]++
}

// DistPktSize is a handler to monitor packet size distribution.
type DistPktSize struct {
	report *Report
}

// Report is a summary of packet distribution
type Report struct {
	dmap distMap
}

func newReport() *Report {
	report := Report{
		dmap: newDistMap(),
	}
	return &report
}

// New is a constructor of DistPktSize handler
func New() modules.Handler {
	hdlr := DistPktSize{}
	hdlr.report = newReport()
	return &hdlr
}

func (x *DistPktSize) ReadPacket(pkt *gopacket.Packet) {
	pktSize := len((*pkt).Data())
	x.report.dmap.count(pktSize)
}

func (x *DistPktSize) MakeReport() modules.Report {
	report := x.report
	x.report = newReport()
	return report
}

func (x *Report) Title() string {
	return "Packet Size Distribution"
}

func (x *Report) String() string {
	lines := []string{}
	for idx, upper := range distUnit {
		d := fmt.Sprintf("...%d", upper)
		line := fmt.Sprintf("%8s: %6d", d, x.dmap[idx])
		lines = append(lines, line)
	}

	lines = append(lines, fmt.Sprintf("%8s: %6d", "1500...",
		x.dmap[len(x.dmap)-1]))

	return strings.Join(lines, "\n")
}
