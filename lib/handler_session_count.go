package tcpswarm

import (
	"bytes"
	"fmt"

	"github.com/google/gopacket"
)

type ssnCount struct {
	numToLeft  int
	numToRight int
}

// SessionCounter is simple counter of session
type SessionCounter struct {
	report *SessionCounterReport
}

// SessionCounterReport is a report structure for SessionCounter
type SessionCounterReport struct {
	counter map[uint64]int
}

func newReport() *SessionCounterReport {
	report := SessionCounterReport{
		counter: make(map[uint64]int),
	}
	return &report
}

// NewSessionCounter is a constructor of SessionCounter
func NewSessionCounter() Handler {
	hdlr := SessionCounter{}
	hdlr.report = newReport()
	return &hdlr
}

// FNV hash based on gopacket.
// See http://isthe.com/chongo/tech/comp/fnv/.
func fnvHash(s []byte) (h uint64) {
	h = fnvBasis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime
	}
	return
}

const fnvBasis = 14695981039346656037
const fnvPrime = 1099511628211

type flowDir int

const (
	toLeft flowDir = iota
	toRight
)

func flowHash(nwFlow, tpFlow *gopacket.Flow, tpType gopacket.LayerType) (uint64, flowDir) {
	nwSrc, nwDst := nwFlow.Endpoints()
	tpSrc, tpDst := tpFlow.Endpoints()

	srcKey := append(nwSrc.Raw(), tpSrc.Raw()...)
	dstKey := append(nwDst.Raw(), tpDst.Raw()...)

	cmp := bytes.Compare(srcKey, dstKey)

	var hv uint64
	var dir flowDir
	if cmp < 0 {
		hv = fnvHash(srcKey) + fnvHash(dstKey)
		dir = toLeft
	} else {
		hv = fnvHash(dstKey) + fnvHash(srcKey)
		dir = toRight
	}
	hv ^= uint64(tpType)
	hv *= fnvPrime

	return hv, dir
}

// ReadPacket reads, parses and analyze a packet, then store result
func (x *SessionCounter) ReadPacket(pkt *gopacket.Packet) {
	// Let's see if the packet is IP (even though the ether type told us)
	nwLayer := (*pkt).NetworkLayer()
	tpLayer := (*pkt).TransportLayer()

	if nwLayer == nil || tpLayer == nil {
		return
	}

	nwFlow := nwLayer.NetworkFlow()
	tpFlow := tpLayer.TransportFlow()
	tpType := tpLayer.LayerType()

	hv, _ := flowHash(&nwFlow, &tpFlow, tpType)

	cnt := x.report.counter[hv]
	x.report.counter[hv] = cnt + 1
}

// MakeReport is a report writer by stored results of pakcet analysis
func (x *SessionCounter) MakeReport() Report {
	report := x.report
	x.report = newReport()
	return report
}

func (x *SessionCounterReport) String() string {
	return fmt.Sprintf("session = %d", len(x.counter))
}
