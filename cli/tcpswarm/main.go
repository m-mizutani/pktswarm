package main

import (
	"fmt"
	"log"

	flags "github.com/jessevdk/go-flags"
	tcpswarm "github.com/m-mizutani/tcpswarm"
)

func main() {
	var opts struct {
		PcapFile  string   `short:"r" description:"Read a pcap file "`
		Interface string   `short:"i" description:"Monitor network interface"`
		Interval  float64  `short:"l" long:"interval" description:"Summary output interval"`
		Modules   []string `short:"m" long:"module" description:"Monitoring modules" default:"session"`
		Version   bool     `short:"v" long:"version" description:"Show version"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	swarm, err := tcpswarm.New(tcpswarm.Config{
		FileName:   opts.PcapFile,
		DeviceName: opts.Interface,
		Handlers:   opts.Modules,
		Interval:   opts.Interval,
	})

	if err != nil {
		log.Fatal("initialize error:", err)
	}
	msgCh, err := swarm.Start()

	for {
		msg := <-msgCh
		if msg == nil {
			log.Println("exit")
			break
		}

		log.Println("================================")
		for _, report := range msg.Reports {
			log.Printf("<< %s >>\n", report.Title())
			fmt.Println(report.String())
		}
	}
}
