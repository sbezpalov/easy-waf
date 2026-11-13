// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"errors"
	"sync"
)

const (
	maxAptLiveLines = 1024
	maxAptLiveBytes = 4 << 20
)

var errAptLiveBackpressure = errors.New("live APT output interrupted: client cannot keep up; inspect the saved package log and operation status")

// Package callbacks only offer bounded live output. The owned delivery worker
// may block on a socket, but it cannot stop pipe draining, heartbeat join or
// command completion. Durable logging remains in runAptPrimary before offer.
type aptLiveDelivery struct {
	sc      *aptStreamConn
	pending chan string
	failed  chan struct{}
	done    chan struct{}
	result  streamEvent // published by closing pending after callbacks have joined

	mu    sync.Mutex
	bytes int
	err   error
}

func newAptLiveDelivery(sc *aptStreamConn) *aptLiveDelivery {
	d := &aptLiveDelivery{sc: sc, pending: make(chan string, maxAptLiveLines), failed: make(chan struct{}), done: make(chan struct{})}
	go d.deliver()
	return d
}

func (d *aptLiveDelivery) failLocked(err error) {
	if d.err == nil {
		d.err = err
		close(d.failed)
	}
}

func (d *aptLiveDelivery) failure() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

func (d *aptLiveDelivery) line(line string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil // live delivery cannot fail or cancel the package command
	}
	if len(line)+1 > maxAptLiveBytes-d.bytes {
		d.failLocked(errAptLiveBackpressure)
		return nil
	}
	select {
	case d.pending <- line:
		d.bytes += len(line) + 1
	default:
		d.failLocked(errAptLiveBackpressure)
	}
	return nil
}

func (d *aptLiveDelivery) send(e streamEvent) bool {
	if err := d.sc.writeEvent(e); err != nil {
		d.mu.Lock()
		d.failLocked(err)
		d.mu.Unlock()
		d.sc.close()
		return false
	}
	return true
}

func (d *aptLiveDelivery) deliver() {
	defer close(d.done)
	defer func() {
		// A failed subscriber must not retain its queued strings for the rest
		// of a long package transaction. Offers stop as soon as err is set.
		d.mu.Lock()
		defer d.mu.Unlock()
		for {
			select {
			case line, ok := <-d.pending:
				if !ok {
					return
				}
				d.bytes -= len(line) + 1
			default:
				return
			}
		}
	}()
	for {
		if err := d.failure(); err != nil {
			_ = d.send(streamEvent{Type: "exit", Code: -1, Error: err.Error()})
			d.sc.close()
			return
		}
		select {
		case <-d.failed:
			continue
		case line, ok := <-d.pending:
			if !ok {
				// Overflow may have happened between the check and receive.
				if d.failure() != nil {
					continue
				}
				_ = d.send(d.result)
				return
			}
			d.mu.Lock()
			d.bytes -= len(line) + 1
			d.mu.Unlock()
			if d.failure() == nil && !d.send(streamEvent{Type: "line", Data: line}) {
				return
			}
		}
	}
}

func (d *aptLiveDelivery) finish(code int, message string) {
	d.result = streamEvent{Type: "exit", Code: code, Error: message}
	close(d.pending)
	<-d.done
}
