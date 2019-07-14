package main

import (
	"fmt"
	"log"
	"time"
)

func main() {
	swarm := NewSwarm()

	go func() {
		for {
			flows := swarm.FlowEngine.Fetch(Query{})
			fmt.Println(len(flows))
			time.Sleep(time.Second)
		}
	}()

	if err := swarm.Loop(); err != nil {
		log.Fatal(err)
	}
}
