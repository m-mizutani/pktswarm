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
	dmap []distMap
}

func newReport() *Report {
	report := Report{
		dmap: []distMap{newDistMap()},
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
	x.report.dmap[len(x.report.dmap)-1].count(pktSize)
}

func (x *DistPktSize) MakeReport() modules.Report {
	const maxMapNum = 10
	report := *x.report
	x.report.dmap = append(x.report.dmap, newDistMap())
	if len(x.report.dmap) > maxMapNum {
		x.report.dmap = x.report.dmap[1:]
	}
	return &report
}

func (x *Report) Title() string {
	return "Packet Size Distribution"
}

func distMapToLine(dmap *[]distMap, idx int, label string) string {
	line := fmt.Sprintf("%8s: ", label)
	for _, d := range *dmap {
		line += fmt.Sprintf("%6d ", d[idx])
	}

	return line
}

func (x *Report) String() string {
	lines := []string{}

	for idx, upper := range distUnit {
		d := fmt.Sprintf("...%d", upper)
		lines = append(lines, distMapToLine(&x.dmap, idx, d))
	}

	lines = append(lines, distMapToLine(&x.dmap, len(distUnit),
		"1500..."))

	return strings.Join(lines, "\n")
}

func (x *Report) Header() []string {
	hdr := []string{}

	for _, upper := range distUnit {
		hdr = append(hdr, fmt.Sprintf("~%d", upper))
	}

	hdr = append(hdr, "1500~")
	return hdr
}

func (x *Report) Row() []string {
	row := []string{}
	for _, d := range x.dmap[len(x.dmap)-1] {
		row = append(row, fmt.Sprintf("%d", d))
	}
	return row
}
