package main

import (
	"fmt"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"
	tcpswarm "github.com/m-mizutani/tcpswarm"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var opts struct {
		PcapFile  string   `short:"r" description:"Read a pcap file "`
		Interface string   `short:"i" description:"Monitor network interface"`
		Interval  float64  `short:"d" long:"interval" description:"Summary output interval"`
		Modules   []string `short:"m" long:"module" description:"Monitoring modules" default:"BasicStats"`
		Version   bool     `short:"v" long:"version" description:"Show version"`
		Quiet     bool     `short:"q" long:"quiet" description:"Show only report body"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
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
	cnt := 0

	_, height, err := terminal.GetSize(0)
	if err != nil {
		height = 10
	} else if height > 2 {
		height -= 2
	}

	for {
		msg := <-msgCh
		if msg == nil {
			log.Println("exit")
			break
		}

		if cnt%height == 0 {
			fmt.Println(msg.Header())
		}
		cnt++

		fmt.Println(msg.Line())
	}
}
