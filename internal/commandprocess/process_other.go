// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package commandprocess

import "os/exec"

// Development platforms retain CommandContext's native parent cancellation.
// Prepare still sets WaitDelay; this does not claim process-tree termination.
func prepare(_ *exec.Cmd) {}

func finish(_ *exec.Cmd) error { return nil }
