// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package testcert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBundleIsCertThenKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := WriteBundle(path, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("first block %#v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "a.example.com" {
		t.Fatalf("cn %s", cert.Subject.CommonName)
	}
	block, _ = pem.Decode(rest)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("key block %#v", block)
	}
}
