// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package commandprocess applies subprocess pipe and process-group policy.
package commandprocess

import (
	"os/exec"
	"time"
)

const WaitDelay = 2 * time.Second

// Prepare configures a fresh CommandContext before Start. It bounds inherited
// pipe waits on every platform and isolates cancellation on Linux/macOS.
func Prepare(cmd *exec.Cmd) {
	cmd.WaitDelay = WaitDelay
	prepare(cmd)
}

// Finish cleans the ordinary command group after Wait. Tracked APT may leave
// successfully started services running by passing stopGroup=false explicitly.
func Finish(cmd *exec.Cmd, stopGroup bool) error {
	if !stopGroup {
		return nil
	}
	return finish(cmd)
}
