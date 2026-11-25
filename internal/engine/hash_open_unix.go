// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package engine

import (
	"golang.org/x/sys/unix"
)

// Opening a FIFO without O_NONBLOCK could block if the path is replaced
// between inspection and opening.
const artifactReadFlags = unix.O_NONBLOCK
