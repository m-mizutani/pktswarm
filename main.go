package main

import (
	"fmt"
	"log"

	flags "github.com/jessevdk/go-flags"
	tcpswarm "github.com/m-mizutani/tcpswarm/lib"
)

func main() {
	var opts struct {
		PcapFile  string `short:"r" description:"Read a pcap file "`
		Interface string `short:"i" description:"Monitor network interface"`
		Version   bool   `short:"v" long:"version" description:"Show version"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	swarm, err := tcpswarm.New(tcpswarm.Config{
		FileName:   opts.PcapFile,
		DeviceName: opts.Interface,
		Handlers:   []string{"session"},
	})

	if err != nil {
		log.Fatal("initialize error:", err)
	}
	fmt.Println(swarm)
	msgCh, err := swarm.Start()

	for {
		msg := <-msgCh
		if msg == nil {
			log.Println("exit")
			break
		}

		for _, report := range msg.Reports {
			fmt.Println(report)
		}
	}
}
