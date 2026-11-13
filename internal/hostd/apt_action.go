// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"errors"
	"fmt"
	"os"
)

// An attached client owns this run, not whichever run later occupies the global
// slot. Mutable lifecycle/results/refs are protected by aptActionMu. Closing
// ready publishes log/logErr once; references keep that descriptor alive.
type aptActionRecord struct {
	phase  aptActionPhase
	code   int
	errMsg string
	refs   int
	ready  chan struct{}
	log    *os.File
	logErr error
}

func newAptActionRecord(phase aptActionPhase) *aptActionRecord {
	return &aptActionRecord{phase: phase, refs: 1, ready: make(chan struct{})}
}

func releaseAptActionLocked(record *aptActionRecord) {
	if record == nil {
		return
	}
	record.refs--
	if record.refs == 0 && record.log != nil {
		_ = record.log.Close()
		record.log = nil
	}
}

func releaseAptAction(record *aptActionRecord) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	releaseAptActionLocked(record)
}

func publishAptActionLogLocked(record *aptActionRecord, err error) {
	if err == nil {
		record.log, err = openAptActionLog(aptActionLogPath())
	}
	record.logErr = err
	close(record.ready)
}

func publishAptActionLog(record *aptActionRecord, err error) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	publishAptActionLogLocked(record, err)
}

func aptActionTryStartLocked() (bool, error) {
	if active, _, _ := aptActionSnapshotLocked(); active {
		return false, nil
	}
	if err := clearAptActionPID(); err != nil {
		return false, fmt.Errorf("clear apt action pid: %w", err)
	}
	releaseAptActionLocked(aptActionCurrent)
	aptActionCurrent = newAptActionRecord(aptLocal)
	return true, nil
}

func aptActionTryStart() (bool, error) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	return aptActionTryStartLocked()
}

// Reserve the record under the same lock that decides primary vs follower.
func acquireAptAction() (*aptActionRecord, bool, error) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	started, err := aptActionTryStartLocked()
	if err != nil {
		return nil, false, err
	}
	record := aptActionCurrent
	record.refs++
	return record, started, nil
}

func finishAptActionLocked(record *aptActionRecord, code int, errMsg string) {
	if record == aptActionCurrent {
		// Clear PID before releasing single-flight ownership. A stale worker
		// must never remove the next run's PID after a test reset/replacement.
		if err := clearAptActionPID(); err != nil {
			logOp("clear apt action pid: %v", err)
		}
	}
	record.phase, record.code, record.errMsg = aptFinished, code, errMsg
	select {
	case <-record.ready:
	default:
		record.logErr = errors.New("apt action log unavailable")
		close(record.ready)
	}
}

func finishAptAction(record *aptActionRecord, code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	finishAptActionLocked(record, code, errMsg)
}

func aptActionFinish(code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	if aptActionCurrent == nil {
		aptActionCurrent = newAptActionRecord(aptLocal)
	}
	finishAptActionLocked(aptActionCurrent, code, errMsg)
}

const unknownAptActionResult = "apt action exit status unavailable after broker restart; inspect the apt action log"

func aptRecordSnapshotLocked(record *aptActionRecord) (active bool, code int, errMsg string) {
	switch record.phase {
	case aptLocal:
		// PID publication/liveness cannot release a local reservation.
		return true, record.code, record.errMsg
	case aptRecovered:
		if record == aptActionCurrent && aptActionPIDAlive() {
			return true, 0, ""
		}
		record.phase, record.code, record.errMsg = aptFinished, -1, unknownAptActionResult
	}
	return false, record.code, record.errMsg
}

func aptRecordSnapshot(record *aptActionRecord) (active bool, code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	return aptRecordSnapshotLocked(record)
}

func aptActionSnapshotLocked() (active bool, code int, errMsg string) {
	if aptActionCurrent == nil {
		if aptActionPIDAlive() {
			aptActionCurrent = newAptActionRecord(aptRecovered)
			publishAptActionLogLocked(aptActionCurrent, nil)
		} else {
			if _, err := readAptActionPID(); !os.IsNotExist(err) {
				return false, -1, unknownAptActionResult
			}
			return false, 0, ""
		}
	}
	return aptRecordSnapshotLocked(aptActionCurrent)
}

func aptActionSnapshot() (active bool, code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	return aptActionSnapshotLocked()
}
