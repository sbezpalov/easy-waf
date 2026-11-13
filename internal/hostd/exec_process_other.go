// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package hostd

import "os/exec"

// Development builds use CommandContext's native parent cancellation. WaitDelay
// also bounds pipe waits; production process-group cleanup is in the Unix file.
func prepareCommandProcess(_ *exec.Cmd) {}

func finishCommandProcess(_ *exec.Cmd, _ bool) error { return nil }
