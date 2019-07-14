package main

import (
	"log"
	"time"
)

type timerCallback struct {
	flow     *Flow
	engine   *FlowEngine
	callback func(flow *Flow, engine *FlowEngine)
}

type timerSlot struct {
	callbacks []timerCallback
}

type timeTable struct {
	timerSlots       []*timerSlot
	duration         time.Duration
	maxDuration      time.Duration
	baseTimestamp    time.Time
	currentTimestamp time.Time
	currentTick      int
	initTimestamp    bool
}

func newTimeTable(slotSize uint, slotDuration time.Duration) *timeTable {
	table := timeTable{
		timerSlots:  make([]*timerSlot, slotSize),
		duration:    slotDuration,
		maxDuration: slotDuration * time.Duration(slotSize),
	}

	for i := range table.timerSlots {
		slot := new(timerSlot)
		slot.callbacks = make([]timerCallback, 0)
		table.timerSlots[i] = slot
	}

	return &table
}

func (x *timeTable) calcTick(timestamp time.Time) int {
	t := timestamp.Sub(x.baseTimestamp)
	return int(t / x.duration)
}

func (x *timeTable) add(callback timerCallback, expire time.Time) {
	tick := x.calcTick(expire)
	if tick > x.currentTick+len(x.timerSlots) {
		log.Fatal("Too long duration", expire, x.currentTimestamp)
	}

	if tick <= x.currentTick {
		tick = x.currentTick + 1
	}

	slot := x.timerSlots[tick%len(x.timerSlots)]
	slot.callbacks = append(slot.callbacks, callback)
}

func (x *timeTable) update(timestamp time.Time) {
	if !x.initTimestamp {
		x.baseTimestamp = timestamp
		x.initTimestamp = true
	}
	x.currentTimestamp = timestamp

	for tick := x.calcTick(timestamp); tick > x.currentTick; x.currentTick++ {
		tp := x.currentTick % len(x.timerSlots)
		for _, cb := range x.timerSlots[tp].callbacks {
			cb.callback(cb.flow, cb.engine)
		}
		x.timerSlots[tp].callbacks = make([]timerCallback, 0)
	}
}
