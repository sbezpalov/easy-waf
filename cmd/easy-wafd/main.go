// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/easy-waf/easy-waf/internal/bootstrap"
	"github.com/easy-waf/easy-waf/internal/cli"
)

// Deprecated binary name: use easy-waf-api. Kept for compatibility with older unit files.
func main() {
	if cli.PrintVersion(os.Args[1:], os.Stdout, "easy-wafd") {
		return
	}

	bootstrap.RunAPI()
}
