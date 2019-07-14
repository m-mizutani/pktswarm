package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

func lookupDevice() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	if len(devs) == 0 {
		return "", errors.New("No available device")
	}

	return devs[0].Name, nil
}

func capture(device, filter string, flowEngine *FlowEngine) error {
	var snapshotLen int32 = 0xffff
	promiscuous := true
	timeout := -1 * time.Second

	if device == "" {
		if dev, err := lookupDevice(); err != nil {
			return errors.Wrap(err, "Fail to lookup available device")
		} else {
			device = dev
		}
	}

	// Open device
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Set filter
	if filter != "" {
		if err = handle.SetBPFFilter(filter); err != nil {
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktCh := packetSource.Packets()

	for pkt := range pktCh {
		flowEngine.ReadPacket(&pkt)
	}

	return nil
	/*
		delta := time.Duration(1 * time.Second)
		tickCh := time.After(delta)

		for {
			select {
			case pkt := <-pktCh:
				current = pkt.Metadata().Timestamp
				if pkt == nil {
					return nil // No more packet
				}
				flowEngine.ReadPacket(&pkt)

			case <-tickCh:
				flowEngine.UpdateTimer(current)
				tickCh = time.After(delta)
			}
		}
	*/
}
