// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDatabaseURL(t *testing.T) {
	const ambient = "postgres://inherited/database"
	const configured = "postgres://configured/database?application_name=$(literal)"
	const override = "postgres://override/database"
	t.Setenv("DATABASE_URL", ambient)
	tests := []struct {
		name     string
		content  string
		override string
		want     string
		empty    bool
	}{
		{name: "missing file", want: ambient},
		{name: "missing entry", content: "DATABASE_URL_OTHER=ignored\n", want: ambient},
		{name: "quoted last value", content: "DATABASE_URL=postgres://older/database\r\nDATABASE_URL=\"" + configured + "\"\r\n", want: configured},
		{name: "single quoted last line", content: "# DATABASE_URL=ignored\nDATABASE_URL='" + configured + "'", want: configured},
		{name: "empty entry", content: "DATABASE_URL=" + configured + "\nDATABASE_URL=\n", empty: true},
		{name: "quoted empty entry", content: "DATABASE_URL=\"\"\n", empty: true},
		{name: "explicit override", content: "DATABASE_URL=''\n", override: override, want: override},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "easy-waf.env")
			if tt.content != "" {
				if err := os.WriteFile(file, []byte(tt.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ResolveDatabaseURL(file, tt.override)
			if tt.empty {
				if got != "" || err == nil || !strings.Contains(err.Error(), "DATABASE_URL is empty") {
					t.Fatal("an empty configured value must stop resolution")
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatal("resolved a different database URL than expected")
			}
		})
	}
}
