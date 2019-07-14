package main

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FlowEngine manages flow mapping of packet. FlowEngine is provided to external
// functions, but it must be created internally.
type FlowEngine struct {
	flowMap       map[flowHashValue]*Flow
	flowTimeTable *timeTable
	timeout       time.Duration
}

// Flow is a combination of L3 and L4 identities:
// - TCP: IP addresses and TCP port numbers
// - UDP: IP addresses and UDP port numbers
// - ICMP: IP addresses
type Flow struct {
	id             string
	hash           flowHashValue
	Client, Server Node
	Protocol       int
	latest         time.Time
	updated        bool
}

type tcpState int

const (
	tcpStateNone tcpState = iota
	tcpStateSyn
	tcpStateSynAck
	tcpStateEstablished
	tcpStateFin
)

type flowDir int

const (
	toClient flowDir = iota
	toServer
)

type Node struct {
	Addr        net.IP
	Port        int
	Last        time.Time
	SentBytes   int
	SentPackets int
	state       tcpState
}

func initFlowEngine(engine *FlowEngine) {
	// engine.timeout = time.Minute * 2
	engine.timeout = time.Second * 5
	engine.flowMap = make(map[flowHashValue]*Flow)
	engine.flowTimeTable = newTimeTable(3600, time.Second)
}

// FNV hash based on gopacket.
// See http://isthe.com/chongo/tech/comp/fnv/.
func fnvHash(s []byte) (h flowHashValue) {
	h = fnvBasis
	for i := 0; i < len(s); i++ {
		h ^= flowHashValue(s[i])
		h *= fnvPrime
	}
	return
}

const fnvBasis = 14695981039346656037
const fnvPrime = 1099511628211

type flowHashValue uint64

func flowHash(nwFlow, tpFlow *gopacket.Flow, tpType gopacket.LayerType) flowHashValue {
	nwSrc, nwDst := nwFlow.Endpoints()
	tpSrc, tpDst := tpFlow.Endpoints()

	srcKey := append(nwSrc.Raw(), tpSrc.Raw()...)
	dstKey := append(nwDst.Raw(), tpDst.Raw()...)

	cmp := bytes.Compare(srcKey, dstKey)

	var hv flowHashValue
	if cmp < 0 {
		hv = fnvHash(srcKey) + fnvHash(dstKey)
	} else {
		hv = fnvHash(dstKey) + fnvHash(srcKey)
	}
	hv ^= flowHashValue(tpType)
	hv *= fnvPrime

	return hv
}

func updateFlowTimeout(flow *Flow, engine *FlowEngine) {
	if flow.updated {
		willExpire := flow.latest.Add(engine.timeout)
		flow.updated = false
		cb := timerCallback{
			flow:     flow,
			engine:   engine,
			callback: updateFlowTimeout,
		}
		engine.flowTimeTable.add(cb, willExpire)
	} else {
		fmt.Println("removed:", *flow)
		delete(engine.flowMap, flow.hash)
	}

	return
}

func setupFlow(flow *Flow, pkt *gopacket.Packet) {
	if ipLayer := (*pkt).Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		flow.Client.Addr = ip.SrcIP
		flow.Server.Addr = ip.DstIP
	}

	if ipLayer := (*pkt).Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		flow.Client.Addr = ip.SrcIP
		flow.Server.Addr = ip.DstIP
	}

	if tcpLayer := (*pkt).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		flow.Client.Port = int(tcp.SrcPort)
		flow.Server.Port = int(tcp.DstPort)
		flow.Protocol = int(layers.IPProtocolTCP)
	}

	if udpLayer := (*pkt).Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		flow.Client.Port = int(udp.SrcPort)
		flow.Server.Port = int(udp.DstPort)
		flow.Protocol = int(layers.IPProtocolUDP)
	}
}

// ReadPacket parses a packet and mapping to flowmap
func (x *FlowEngine) ReadPacket(pkt *gopacket.Packet) {
	x.flowTimeTable.update((*pkt).Metadata().Timestamp)

	// Let's see if the packet is IP (even though the ether type told us)
	nwLayer := (*pkt).NetworkLayer()
	tpLayer := (*pkt).TransportLayer()

	if nwLayer == nil || tpLayer == nil {
		return
	}

	nwFlow := nwLayer.NetworkFlow()
	tpFlow := tpLayer.TransportFlow()
	tpType := tpLayer.LayerType()

	hv := flowHash(&nwFlow, &tpFlow, tpType)
	// TODO: Consider hash collision
	flow, ok := x.flowMap[hv]
	if !ok {
		flow = &Flow{hash: hv}
		setupFlow(flow, pkt)
		x.flowMap[hv] = flow

		cb := timerCallback{
			flow:     flow,
			engine:   x,
			callback: updateFlowTimeout,
		}
		willExpire := (*pkt).Metadata().Timestamp.Add(x.timeout)
		x.flowTimeTable.add(cb, willExpire)
	} else {
		flow.updated = true
	}

	flow.latest = (*pkt).Metadata().Timestamp

	return
}

type Query struct{}

func (x *FlowEngine) Fetch(query Query) []*Flow {
	flowSet := make([]*Flow, len(x.flowMap))
	idx := 0
	for _, flow := range x.flowMap {
		flowSet[idx] = flow
		idx++
	}
	return flowSet
}
