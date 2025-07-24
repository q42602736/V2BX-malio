package counter

import (
	"sync"
	"sync/atomic"
)

type TrafficCounter struct {
	counters sync.Map
}

type TrafficStorage struct {
	UpCounter   atomic.Int64
	DownCounter atomic.Int64
}

func NewTrafficCounter() *TrafficCounter {
	return &TrafficCounter{}
}

func (c *TrafficCounter) GetCounter(id string) *TrafficStorage {
	if cts, ok := c.counters.Load(id); ok {
		return cts.(*TrafficStorage)
	}
	newStorage := &TrafficStorage{}
	if cts, loaded := c.counters.LoadOrStore(id, newStorage); loaded {
		return cts.(*TrafficStorage)
	}
	return newStorage
}

func (c *TrafficCounter) GetUpCount(id string) int64 {
	if cts, ok := c.counters.Load(id); ok {
		return cts.(*TrafficStorage).UpCounter.Load()
	}
	return 0
}

func (c *TrafficCounter) GetDownCount(id string) int64 {
	if cts, ok := c.counters.Load(id); ok {
		return cts.(*TrafficStorage).DownCounter.Load()
	}
	return 0
}

func (c *TrafficCounter) Len() int {
	length := 0
	c.counters.Range(func(_, _ interface{}) bool {
		length++
		return true
	})
	return length
}

func (c *TrafficCounter) Reset(id string) {
	if cts, ok := c.counters.Load(id); ok {
		cts.(*TrafficStorage).UpCounter.Store(0)
		cts.(*TrafficStorage).DownCounter.Store(0)
	}
}

func (c *TrafficCounter) Delete(id string) {
	c.counters.Delete(id)
}

func (c *TrafficCounter) Rx(id string, n int) {
	cts := c.GetCounter(id)
	cts.DownCounter.Add(int64(n))
}

func (c *TrafficCounter) Tx(id string, n int) {
	cts := c.GetCounter(id)
	cts.UpCounter.Add(int64(n))
}
