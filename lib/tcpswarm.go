package tcpswarm

import (
	"errors"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PktSwarm is a main structure
type PktSwarm struct {
	pcap *pcap.Handle
}

// Config for PktSwarm constructor
type Config struct {
	DeviceName string
	FileName   string
}

// Message is data structure of periodic monitoring result
type Message struct {
	Count int
}

// New is a constructor of PktSwarm
func New(config Config) (*PktSwarm, error) {
	swarm := PktSwarm{}

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

	return &swarm, nil
}

// Start involve monitor loop and returns channel
func (x *PktSwarm) Start() (<-chan Message, error) {
	if x.pcap == nil {
		return nil, errors.New("Network interface is not available")
	}

	ch := make(chan Message)

	go func() {
		count := 0
		packetSource := gopacket.NewPacketSource(x.pcap, x.pcap.LinkType())
		pktCh := packetSource.Packets()
		timeoutCh := time.After(1 * time.Second)

		for {
			select {
			case <-pktCh:
				count++
			case <-timeoutCh:
				msg := Message{Count: count}
				ch <- msg
				count = 0
				timeoutCh = time.After(1 * time.Second)
			}
		}
	}()
	return ch, nil
}
