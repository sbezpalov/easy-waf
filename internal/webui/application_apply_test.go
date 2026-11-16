// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestApplicationApplyFeedback(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute application interaction tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"save_success", "save_manual", "save_legacy", "save_rejected", "save_missing_cert", "mode_success", "mode_manual", "mode_legacy", "mode_rejected", "mode_cancelled", "maintenance_success", "maintenance_manual", "maintenance_rejected", "maintenance_cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "-e", applicationApplyTest, scenario)
			cmd.Stdin = bytes.NewReader(page)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("application Apply feedback: %v\n%s", err, output)
			}
		})
	}
}

const applicationApplyTest = `
const assert = require('node:assert/strict');
const vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const scenario = process.argv[1];
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    const classes = new Set();
    elements.set(id, {value: '', checked: false, disabled: false, textContent: '',
      classList: {toggle: (name, on) => on ? classes.add(name) : classes.delete(name), contains: name => classes.has(name)}});
  }
  return elements.get(id);
}
Object.entries({'app-edit-id': 'fixture-app', 'listen-mode': 'http_only', name: 'Fixture',
  host: 'fixture.invalid', backend: '127.0.0.1', port: '8123', profile: 'balanced'})
  .forEach(([id, value]) => {element(id).value = value});
if (scenario === 'save_missing_cert') element('listen-mode').value = 'https_only';
const requests = [], notices = [];
let cleared = 0, collapsed = 0, refreshed = 0;
const context = {pendingApply: true, document: {getElementById: element},
  appsListCache: [{id: 'fixture-app', security: {mode: 'balanced'}}],
  hdr: () => ({}), encodeURIComponent,
  fetch: async (path, init) => {
    requests.push([path, init]);
    return {ok: !scenario.endsWith('_rejected'), headers: {get: name => {assert.equal(name, 'X-Easy-Waf-Applied'); return scenario.endsWith('_legacy') ? null : scenario.endsWith('_manual') ? 'false' : 'true'}}};
  },
  withBusy: async (button, operation) => operation(),
  toast: (...args) => notices.push(args), apiMessage: async () => 'Apply rejected',
  confirmDialog: async () => !scenario.endsWith('_cancelled'), loadApps: async () => {refreshed++},
  parseBackendServers: () => [], collectRestrictedPaths: () => [], collectPathPolicy: () => null,
  withBodyPolicy: value => value,
  clearAppFormFields: () => {cleared++}, setAppFormCollapsed: on => {if (on) collapsed++}};
vm.createContext(context);
function include(from, until) {
  const start = page.indexOf(from), end = page.indexOf(until, start);
  assert.ok(start >= 0 && end > start, 'embedded handler missing: ' + from);
  vm.runInContext(page.slice(start, end), context);
}
include('  function markPendingApply(', '  function copyBtn(');
include('  async function setAppMaintenance(', '  function fillAppFormFromApp(');
include("  document.getElementById('save').onclick =", '  const HOST_CRITICAL_UNITS');
async function run() {
  const select = {value: scenario === 'mode_cancelled' ? 'reverse-proxy-only' : 'full'};
  if (scenario.startsWith('save_')) await element('save').onclick();
  else if (scenario.startsWith('mode_')) await context.postAppModeChange('fixture-app', select.value, select);
  else await context.setAppMaintenance('fixture-app', true, {});
  if (scenario.endsWith('_cancelled') || scenario === 'save_missing_cert') {
    assert.equal(requests.length, 0, 'cancelled or invalid input must not mutate');
    assert.equal(context.pendingApply, true);
    assert.equal(cleared + collapsed + refreshed, 0);
    if (scenario === 'mode_cancelled') assert.equal(select.value, 'balanced');
    return;
  }
  assert.equal(requests.length, 1, 'one mutation; no extra explicit Apply request');
  assert.equal(requests[0][1].method, 'POST');
  assert.equal(requests[0][0], scenario.startsWith('save_') ? '/api/v1/applications' : scenario.startsWith('mode_') ? '/api/v1/applications/fixture-app/security/mode' : '/api/v1/applications/fixture-app/maintenance');
  if (scenario.endsWith('_rejected')) {
    assert.equal(context.pendingApply, true, 'rejected mutation must preserve pending state');
    assert.equal(cleared + collapsed + refreshed, 0, 'keep rejected form for correction');
    assert.ok(notices.some(([, kind]) => kind === 'err'));
    if (scenario === 'mode_rejected') assert.equal(select.value, 'balanced');
  } else {
    const applied = scenario.endsWith('_success');
    assert.equal(context.pendingApply, !applied, 'pending must match server Apply outcome');
    for (const id of ['nav-config-pending', 'apps-pending-banner']) {
      assert.equal(element(id).classList.contains('hidden'), applied, 'indicator must match actual Apply outcome');
    }
    assert.equal(refreshed, 1);
    assert.ok(notices.some(([text, kind]) => kind === 'ok' && (applied ? /applied/i.test(text) : /Apply on Config/i.test(text))), 'report actual Apply outcome');
    assert.equal(cleared, scenario.startsWith('save_') ? 1 : 0);
    assert.equal(collapsed, scenario.startsWith('save_') ? 1 : 0);
  }
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
