// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package engine

import (
	"os"

	"golang.org/x/sys/unix"
)

func openArtifactForHash(path string) (*os.File, error) {
	// The path can be replaced between Stat and Open. Opening a FIFO without
	// O_NONBLOCK could hold a diagnostic or edge operation waiting for a writer.
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
