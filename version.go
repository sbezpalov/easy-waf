// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package easywaf identifies the source version embedded in the running binary.
package easywaf

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version returns the repository VERSION captured at build time.
func Version() string { return strings.TrimSpace(versionFile) }
