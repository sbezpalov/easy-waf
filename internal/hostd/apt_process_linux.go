// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
)

// stat's comm field can contain spaces and ')'. Only fields after its last ')'
// have stable whitespace boundaries: state is field 3, starttime field 22.
func parseLinuxAptStat(data []byte, pid int) (byte, uint64, error) {
	text := string(data)
	begin, end := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if begin < 0 || end <= begin {
		return 0, 0, errors.New("invalid apt process stat")
	}
	actualPID, err := strconv.Atoi(strings.TrimSpace(text[:begin]))
	fields := strings.Fields(text[end+1:])
	if err != nil || actualPID != pid || len(fields) < 20 || len(fields[0]) != 1 {
		return 0, 0, errors.New("invalid apt process stat identity")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid apt process stat start time")
	}
	return fields[0][0], ticks, nil
}

func readLinuxAptStat(root *os.Root, pid int) (byte, uint64, error) {
	f, err := root.Open("stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	data, err := readBoundedAptMetadata(f, 4096)
	if err != nil {
		return 0, 0, err
	}
	return parseLinuxAptStat(data, pid)
}

func linuxAptBootID(procRoot string) (string, error) {
	f, err := os.Open(filepath.Join(procRoot, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := readBoundedAptMetadata(f, maxAptPIDBytes)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(data))
	id, err := uuid.Parse(text)
	if err != nil || id.String() != text {
		return "", errors.New("invalid Linux boot ID")
	}
	return text, nil
}

func captureAptProcessIdentity(pid int) (aptProcessIdentity, error) {
	// Retain one proc directory descriptor. Reads never switch to a later
	// process that happens to reuse this PID while inspection is in progress.
	root, err := os.OpenRoot(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return aptProcessIdentity{}, err
	}
	defer root.Close()
	_, ticks, err := readLinuxAptStat(root, pid)
	if err != nil {
		return aptProcessIdentity{}, err
	}
	boot, err := linuxAptBootID("/proc")
	return aptProcessIdentity{pid: pid, bootID: boot, startTicks: ticks}, err
}

func resolveAptProcess(identity aptProcessIdentity) (*aptProcessIdentity, error) {
	return resolveLinuxAptProcess("/proc", identity)
}

func resolveLinuxAptProcess(procRoot string, identity aptProcessIdentity) (*aptProcessIdentity, error) {
	root, err := os.OpenRoot(filepath.Join(procRoot, strconv.Itoa(identity.pid)))
	if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	state, ticks, err := readLinuxAptStat(root, identity.pid)
	if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if state == 'Z' || state == 'X' || state == 'x' {
		return nil, nil
	}
	boot, err := linuxAptBootID(procRoot)
	if err != nil {
		return nil, err
	}
	if identity.bootID != "" {
		if identity.bootID != boot || identity.startTicks != ticks {
			return nil, nil
		}
	} else {
		// Old files have no process epoch. An arbitrary live PID is not
		// evidence of APT; upgrade a recognized live apt-get to a pinned epoch.
		executable, err := root.Readlink("exe")
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimSuffix(executable, " (deleted)") != binAptGet {
			return nil, nil
		}
	}
	return &aptProcessIdentity{pid: identity.pid, bootID: boot, startTicks: ticks}, nil
}
