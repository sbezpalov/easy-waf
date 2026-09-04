// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// easy-waf-hostd is the root privilege broker for host management (unix socket).
package main

import (
	"fmt"
	"os"

	"github.com/easy-waf/easy-waf/internal/hostd"
)

func main() {
	if len(os.Args) >= 4 && os.Args[1] == "revert" {
		if err := hostd.RunRevert(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "[easy-waf-hostd] revert: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 {
		fmt.Fprintf(os.Stderr, "usage: %s | %s revert <nft|netplan> <token>\n", os.Args[0], os.Args[0])
		os.Exit(2)
	}
	if err := hostd.ServeDefault(); err != nil {
		fmt.Fprintf(os.Stderr, "[easy-waf-hostd] %v\n", err)
		os.Exit(1)
	}
}
