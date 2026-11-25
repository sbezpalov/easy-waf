// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/easy-waf/easy-waf/internal/cli"
	"github.com/easy-waf/easy-waf/internal/mcpd"
)

func main() {
	if cli.PrintVersion(os.Args[1:], os.Stdout, "easy-waf-mcpd") {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := mcpd.Run(ctx)
	stop()
	if err != nil {
		log.Fatal(err)
	}
}
