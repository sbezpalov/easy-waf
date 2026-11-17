// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log"

	"github.com/easy-waf/easy-waf/internal/webui/generator"
)

func main() {
	source := flag.String("source", "./src", "directory containing web UI source partials")
	output := flag.String("output", "./dist/index.html", "generated bundle path")
	flag.Parse()

	if err := generator.WriteDefault(*source, *output); err != nil {
		log.Fatal(err)
	}
}
