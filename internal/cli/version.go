// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"

	"github.com/easy-waf/easy-waf"
)

// PrintVersion handles a standalone version flag before any service setup.
func PrintVersion(args []string, output io.Writer, command string) bool {
	if len(args) != 1 || (args[0] != "--version" && args[0] != "-version") {
		return false
	}
	_, _ = fmt.Fprintf(output, "%s %s\n", command, easywaf.Version())
	return true
}
