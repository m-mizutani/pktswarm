package main

// Swarm is a main structure of tcpswarm. It handles both of packet capture and http server.
type Swarm struct {
	Device     string
	Filter     string
	Host       string
	Port       int
	FlowEngine FlowEngine
}

// NewSwarm is a constructor of Swarm.
func NewSwarm() *Swarm {
	swarm := Swarm{
		Host: "localhost",
		Port: 8080,
	}
	initFlowEngine(&swarm.FlowEngine)
	return &swarm
}

// Loop starts packet capture and http server.
func (x *Swarm) Loop() error {
	if err := capture(x.Device, x.Filter, &x.FlowEngine); err != nil {
		return err
	}

	return nil
}
