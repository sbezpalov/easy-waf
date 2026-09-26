// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenStagedFileRejectsPathOutsideStaging(t *testing.T) {
	if _, err := openStagedFile("/etc/passwd"); err == nil {
		t.Fatal("expected path outside staging to fail")
	}
}

func TestOpenStagedFileRejectsMissingFile(t *testing.T) {
	if _, err := openStagedFile("/var/lib/easy-waf/staging/missing"); err == nil {
		t.Fatal("expected missing file to fail")
	}
}

func TestValidateNftFileRejectsInclude(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.nft")
	good := filepath.Join(dir, "good.nft")
	if err := os.WriteFile(bad, []byte("table inet t { }\ninclude \"/etc/shadow\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("table inet t { }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNftFile(bad); err == nil {
		t.Fatal("ruleset with include accepted")
	}
	if err := validateNftFile(good); err != nil {
		t.Fatal(err)
	}
}
