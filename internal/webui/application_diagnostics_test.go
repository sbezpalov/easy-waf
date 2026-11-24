// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestApplicationDiagnosticsUIContract(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`class="secondary btn-app-diagnostics" data-viewer-action="true"`,
		`aria-expanded="false" aria-controls=`,
		`/api/v1/applications/`,
		`/diagnostics`,
		`DNS resolution does not prove that an address points to this appliance.`,
		`data-diagnostic-state=`,
		`Checking DNS, certificate material, applied edge state, and HAProxy runtime`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("application diagnostics UI missing %q", want)
		}
	}
}

func TestApplicationDiagnosticsInteraction(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for UI interaction tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", applicationDiagnosticsInteractionTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("application diagnostics interaction: %v\n%s", err, output)
	}
}

const applicationDiagnosticsInteractionTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  function appDiagnosticsDOMID(');
const end = page.indexOf("  document.getElementById('btn-totp-setup').onclick", start);
assert.ok(start >= 0 && end > start, 'missing application diagnostics functions');

function esc(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function makePanel() {
  const classes = new Set(['hidden']);
  return {innerHTML: '', classList: {toggle: (name, on) => on ? classes.add(name) : classes.delete(name),
    contains: name => classes.has(name)}};
}
function response(body, status = 200) {
  return {ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body)};
}
const payload = {application_id: 'fixture/app', checked_at: '2026-11-17T12:00:00Z', status: 'failed',
  summary: 'Backend <down>', steps: [
    {id: 'dns', label: 'DNS', status: 'ok', summary: 'Resolved', evidence: ['203.0.113.4']},
    {id: 'backend', label: 'Backend', status: 'failed', summary: '<img src=x onerror=alert(1)>', evidence: ['s1: DOWN']},
    {id: 'runtime', label: 'HAProxy runtime', status: 'unknown', summary: 'Unavailable', evidence: []},
    {id: 'tls', label: 'TLS', status: 'not_applicable', summary: 'HTTP only', evidence: []}
  ]};

async function run() {
  let panel = makePanel(), calls = [];
  const context = {console, encodeURIComponent, esc,
    statusBadge: (label, tone) => '<badge data-tone="' + esc(tone) + '">' + esc(label) + '</badge>',
    stateView: (state, message) => '<state data-state="' + esc(state) + '">' + esc(message) + '</state>',
    formatHostTime: value => value, hdr: () => ({Authorization: 'fixture'}),
    fetch: async path => {calls.push(path); return response(payload)},
    document: {getElementById: () => panel},
    withBusy: async (_button, operation) => operation()};
  vm.createContext(context);
  vm.runInContext(page.slice(start, end), context);

  const rendered = context.renderApplicationDiagnostics(payload);
  assert.match(rendered, /Issue found/);
  assert.match(rendered, /data-tone="danger">Failed/);
  assert.match(rendered, /data-tone="unknown">Unknown/);
  assert.match(rendered, /Not applicable/);
  assert.match(rendered, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(rendered, /<img/);

  await context.loadApplicationDiagnostics('fixture/app', panel);
  assert.equal(calls[0], '/api/v1/applications/fixture%2Fapp/diagnostics');
  assert.match(panel.innerHTML, /Availability diagnosis/);

  const attrs = {'aria-controls': 'fixture-panel', 'aria-expanded': 'false', 'data-id': 'fixture/app'};
  const button = {textContent: 'Diagnose', disabled: false,
    getAttribute: name => attrs[name], setAttribute: (name, value) => {attrs[name] = value},
    removeAttribute: name => {delete attrs[name]}};
  await context.toggleApplicationDiagnostics(button);
  assert.equal(attrs['aria-expanded'], 'true');
  assert.equal(button.textContent, 'Hide diagnostics');
  assert.equal(panel.classList.contains('hidden'), false);
  await context.toggleApplicationDiagnostics(button);
  assert.equal(attrs['aria-expanded'], 'false');
  assert.equal(button.textContent, 'Diagnose');
  assert.equal(panel.classList.contains('hidden'), true);

  context.fetch = async () => {throw Error('fixture offline')};
  panel = makePanel();
  await context.loadApplicationDiagnostics('fixture', panel);
  assert.match(panel.innerHTML, /could not be reached/);
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
