// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf"
)

func TestPrintVersion(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-version"}, nil, {"apt-worker"}, {"doctor"}, {"--version", "extra"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var output bytes.Buffer
			want := len(args) == 1 && strings.HasSuffix(args[0], "version")
			if got := PrintVersion(args, &output, "easy-waf-api"); got != want {
				t.Fatalf("handled %v, want %v", got, want)
			}
			if want {
				if got := output.String(); got != "easy-waf-api "+easywaf.Version()+"\n" || easywaf.Version() == "" {
					t.Fatalf("version output %q", got)
				}
			} else if output.Len() != 0 {
				t.Fatal("normal command produced version output")
			}
		})
	}
}
