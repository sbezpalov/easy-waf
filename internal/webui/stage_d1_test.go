// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"strings"
	"testing"
)

func TestStageD1CrossScreenAccessibilityContracts(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`<label for="edge-tcp-services"`,
		`aria-describedby="edge-tcp-services-hint"`,
		`<label for="edge-tls-passthrough"`,
		`aria-describedby="edge-tls-passthrough-hint"`,
		`<label class="field-label" for="net-netplan-yaml">`,
		`<label class="field-label" for="net-firewall-rules">`,
		`aria-label="Role for ' + esc(u.username)`,
		`.toast-warn { border-left-color: var(--color-warning); }`,
		`warn: { label: 'Warning', role: 'status' }`,
		`el.setAttribute('role', variant.role)`,
		`el.setAttribute('aria-label', variant.label + ' notification')`,
		`aria-live="polite" aria-relevant="additions"`,
		`Use <strong>https://this-host:8443</strong>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Stage D1 UI contract missing %q", want)
		}
	}
	for _, bad := range []string{
		`http://this-host:8000`,
		`style="min-width:22rem`,
		`style="min-width:24rem`,
	} {
		if strings.Contains(html, bad) {
			t.Errorf("Stage D1 reflow/login regression remains: %q", bad)
		}
	}
}
