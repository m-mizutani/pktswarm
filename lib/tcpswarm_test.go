package tcpswarm_test

import (
	"testing"
	"time"

	"github.com/m-mizutani/tcpswarm/lib"
	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	sw, err := tcpswarm.New(tcpswarm.Config{
		FileName: "../testdata/d1.pcap",
		Handlers: []string{"SessionCount"},
	})
	assert.Nil(t, err)

	ch, err := sw.Start()
	assert.Nil(t, err)
	recvCount := 0
	timeout := false

	select {
	case msg := <-ch:
		assert.NotEqual(t, 0, len(msg.Reports))
		recvCount++
	case <-time.After(2 * time.Second):
		timeout = true
	}

	assert.False(t, timeout)
	assert.NotEqual(t, 0, recvCount)
}
