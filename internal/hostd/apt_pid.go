// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const maxAptPIDBytes = 128

// Only absence of the bookkeeping file means no saved process. ENOENT from
// another inspection input (for example boot_id) is verification uncertainty.
var errNoSavedAptProcess = errors.New("no saved apt process")

type aptProcessIdentity struct {
	pid        int
	bootID     string // empty only for legacy records/non-Linux development
	startTicks uint64
}

func parseAptActionPID(data []byte) (aptProcessIdentity, error) {
	fields := strings.Fields(string(data))
	if len(fields) != 1 && len(fields) != 4 {
		return aptProcessIdentity{}, errors.New("invalid apt process metadata")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return aptProcessIdentity{}, errors.New("invalid apt process PID")
	}
	identity := aptProcessIdentity{pid: pid}
	if len(fields) == 1 {
		return identity, nil
	}
	boot, err := uuid.Parse(fields[2])
	if fields[1] != "v1" || err != nil || boot.String() != fields[2] {
		return aptProcessIdentity{}, errors.New("invalid apt process version/boot ID")
	}
	ticks, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return aptProcessIdentity{}, errors.New("invalid apt process start time")
	}
	identity.bootID, identity.startTicks = fields[2], ticks
	return identity, nil
}

func readBoundedAptMetadata(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("apt process metadata exceeds limit")
	}
	return data, nil
}

func readAptActionPID() ([]byte, error) {
	path := aptActionPIDPath()
	var f *os.File
	var err error
	if underStateDir(path) {
		f, err = stateOpenFile(path)
	} else {
		f, err = os.Open(path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBoundedAptMetadata(f, maxAptPIDBytes)
}

func storeAptActionPID(data []byte) error {
	path := aptActionPIDPath()
	if underStateDir(path) {
		return stateWriteFile(path, data, 0o600)
	}
	return writeFileAtomic(path, data, 0o600)
}

func writeAptActionPID(pid int) error {
	if pid <= 0 {
		return errors.New("invalid apt process PID")
	}
	identity, err := captureAptProcessIdentity(pid)
	if err != nil {
		return err
	}
	// Keep the leading numeric PID readable by older brokers during rollback.
	data := fmt.Sprintf("%d\n", pid)
	if identity.bootID != "" {
		data += fmt.Sprintf("v1 %s %d\n", identity.bootID, identity.startTicks)
	}
	return storeAptActionPID([]byte(data))
}

func recoverAptActionProcess() (*aptProcessIdentity, error) {
	data, err := readAptActionPID()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNoSavedAptProcess
		}
		return nil, err
	}
	identity, err := parseAptActionPID(data)
	if err != nil {
		return nil, err
	}
	if identity.pid <= 0 { // legacy invalid/stale PID cannot name a process
		return nil, nil
	}
	return resolveAptProcess(identity)
}
