// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hostd

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func prepareCommandProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killCommandGroup(cmd) }
}

func killCommandGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil || cmd.Process.Pid <= 0 {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func finishCommandProcess(cmd *exec.Cmd, stopGroup bool) error {
	if !stopGroup {
		return nil
	}
	err := killCommandGroup(cmd)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
