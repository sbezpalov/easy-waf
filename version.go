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

//go:embed LICENSE
var licenseFile string

//go:embed NOTICE
var noticeFile string

// Version returns the repository VERSION captured at build time.
func Version() string { return strings.TrimSpace(versionFile) }

// LicenseText returns the terms shipped with this build.
func LicenseText() string { return licenseFile }

// NoticeText returns the attribution and third-party notices shipped with this build.
func NoticeText() string { return noticeFile }
