// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func TestWriteCertificateResourceRejectsTraversalID(t *testing.T) {
	_, _, _, _, err := WriteCertificateResource(t.TempDir(), "../../acme/webroot/.well-known/acme-challenge", &certificate.Resource{})
	if err == nil || !strings.Contains(err.Error(), "certificate id") {
		t.Fatalf("expected certificate id error, got %v", err)
	}
}
