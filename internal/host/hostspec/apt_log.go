// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import "time"

const (
	MaxAPTLogBytes        = 64 << 20
	APTLogChunkBytes      = 32 << 10
	MaxAPTLogTextBytes    = 3 * MaxAPTLogBytes // JSON replaces each invalid byte with U+FFFD.
	MaxAPTLogFrameBytes   = 256 << 10          // Worst-case escaped source chunk plus framing.
	APTLogDownloadTimeout = 2 * time.Minute
)
