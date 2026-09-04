// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

func emitDpkgLockHint(func(string) error) {}
func dpkgLockBusy() bool                  { return false }
