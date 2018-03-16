package utils

import (
	"sync"
	"time"
)

const (
	tw_epoch = int64(1521185317296000000)
	time_offset = 17
	node_offset = 12
	max_sequence = int64(4095)
)

type Generator struct {
	last_timestamp int64
	sequence int64
	NodeID int64
	mtx sync.Mutex
}

//nodeID < 32
func (g *Generator) GenID() int64 {
	id := int64(0)
	g.mtx.Lock()
	defer g.mtx.Unlock()
	timestamp := (time.Now().UnixNano() - tw_epoch) / 1000000
	if timestamp == g.last_timestamp {
		if g.sequence < max_sequence {
			g.sequence++
		}else {
			g.sequence = 0
			for { //阻塞至下一毫秒
				timestamp = (time.Now().UnixNano() - tw_epoch) / 1000000
				if timestamp != g.last_timestamp {
					g.last_timestamp = timestamp
					break
				}
			}
		}
	}else {
		g.last_timestamp = timestamp
		g.sequence = 0
	}
	id |= (timestamp << time_offset) | (g.NodeID << node_offset) | g.sequence
	return id
}