package tcpswarm

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/m-mizutani/tcpswarm/lib/modules"
	"github.com/m-mizutani/tcpswarm/lib/modules/BasicStats"
	"github.com/m-mizutani/tcpswarm/lib/modules/DistPktSize"
	"github.com/m-mizutani/tcpswarm/lib/modules/SessionCount"
)

// TCPSwarm is a main structure
type TCPSwarm struct {
	pcap     *pcap.Handle
	handlers []modules.Handler
	interval float64
}

// Config for TcpSwarm constructor
type Config struct {
	DeviceName string
	FileName   string
	Handlers   []string
	Interval   float64
}

// Message is data structure of periodic monitoring result
type Message struct {
	Reports []modules.Report
}

// New is a constructor of TcpSwarm
func New(config Config) (*TCPSwarm, error) {
	handlerMap := map[string](func() modules.Handler){
		"SessionCount": SessionCount.New,
		"DistPktSize":  DistPktSize.New,
		"BasicStats":   BasicStats.New,
	}
	swarm := TCPSwarm{
		interval: 1.0,
	}

	// Set devices
	if config.FileName != "" && config.DeviceName != "" {
		return nil, errors.New("Do not set both of FileName and DeviceName at once")
	}

	switch {
	case config.FileName != "":
		handle, err := pcap.OpenOffline(config.FileName)
		if err != nil {
			return nil, err
		}
		swarm.pcap = handle

	case config.DeviceName != "":
		var snapshotLen int32 = 0xffff
		promiscuous := true
		timeout := -1 * time.Second

		handle, err := pcap.OpenLive(config.DeviceName, snapshotLen, promiscuous, timeout)
		if err != nil {
			return nil, err
		}
		swarm.pcap = handle

	default:
		return nil, errors.New("One of FileName or DeviceName is required")
	}

	// Setup handlers
	for _, handlerName := range config.Handlers {
		constructor := handlerMap[handlerName]
		if constructor == nil {
			return nil, errors.New("No such handler: " + handlerName)
		}

		hdlr := constructor()
		swarm.handlers = append(swarm.handlers, hdlr)
	}

	if len(swarm.handlers) == 0 {
		return nil, errors.New("One or more handlers are required")
	}

	// Set interval
	if config.Interval > 0 {
		swarm.interval = config.Interval
	}

	return &swarm, nil
}

func publishMessage(ch chan *Message, handlers *[]modules.Handler) {
	msg := Message{}
	for _, hdlr := range *handlers {
		msg.Reports = append(msg.Reports, hdlr.MakeReport())
	}
	ch <- &msg
}

// Start involve monitor loop and returns channel
func (x *TCPSwarm) Start() (<-chan *Message, error) {
	if x.pcap == nil {
		return nil, errors.New("Network interface is not available")
	}

	ch := make(chan *Message)

	go func() {
		packetSource := gopacket.NewPacketSource(x.pcap, x.pcap.LinkType())
		pktCh := packetSource.Packets()
		delta := time.Duration(x.interval * float64(time.Second))
		timeoutCh := time.After(delta)
		defer close(ch)

		for {
			select {
			case pkt := <-pktCh:
				if pkt == nil {
					publishMessage(ch, &x.handlers)
					return // No more packet
				}
				for _, hdlr := range x.handlers {
					hdlr.ReadPacket(&pkt)
				}
			case <-timeoutCh:
				publishMessage(ch, &x.handlers)
				timeoutCh = time.After(delta)
			}
		}
	}()
	return ch, nil
}

func (x *TCPSwarm) Stop() error {
	return nil
}

// Header converts report(s) to line header
func (x *Message) Header() string {
	var items []string
	for _, report := range x.Reports {
		items = append(items, report.Header()...)
	}

	var row []string
	for _, item := range items {
		row = append(row, fmt.Sprintf("%10s", item))
	}

	return strings.Join(row, " ")
}

// Line converts report(s) to one line text
func (x *Message) Line() string {
	var items []string
	for _, report := range x.Reports {
		items = append(items, report.Row()...)
	}

	var row []string
	for _, item := range items {
		row = append(row, fmt.Sprintf("%10s", item))
	}

	return strings.Join(row, " ")
}
