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

func TestApplicationControls(t *testing.T) {
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
	cmd := exec.CommandContext(ctx, node, "-e", applicationControlsTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("application controls: %v\n%s", err, output)
	}
}

const applicationControlsTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
function include(context, from, until) {
  const start = page.indexOf(from), end = page.indexOf(until, start);
  assert.ok(start >= 0 && end > start, 'missing handler: ' + from);
  vm.runInContext(page.slice(start, end), context);
}
async function run() {
  for (const scenario of ['auto', 'manual', 'legacy', 'cancel', 'reject', 'other_editor']) {
    const id = 'fixture/app', notices = [], calls = [];
    let cleared = 0, collapsed = 0, refreshed = 0;
    const context = {appsListCache: [{id, name: 'Fixture', public_host: 'fixture.invalid'}],
      document: {getElementById: () => ({value: scenario === 'other_editor' ? 'other' : id})},
      confirmDialog: async (text, options) => {
        assert.match(text, /Fixture/); assert.match(text, /fixture.invalid/);
        assert.equal(options.danger, true);
        return scenario !== 'cancel';
      },
      withBusy: async (button, fn) => fn(), hdr: () => ({}), encodeURIComponent,
      fetch: async (path, init) => {
        calls.push([path, init]);
        return {ok: scenario !== 'reject', status: scenario === 'reject' ? 422 : 204,
          headers: {get: () => scenario === 'manual' ? 'false' : scenario === 'legacy' ? null : 'true'},
          json: () => {throw Error('204 has no JSON body')}};
      },
      markPendingApply: on => {context.pending = on}, pending: true,
      toast: (...args) => notices.push(args), apiMessage: async () => 'Apply failed',
      clearAppFormFields: () => {cleared++}, setAppFormCollapsed: on => {if (on) collapsed++},
      loadApps: async () => {refreshed++}};
    vm.createContext(context);
    include(context, '  async function deleteApplication(', '  async function setAppMaintenance(');
    await context.deleteApplication(id, {});
    if (scenario === 'cancel') { assert.equal(calls.length, 0); assert.equal(refreshed, 0); continue; }
    assert.equal(calls.length, 1); assert.equal(calls[0][0], '/api/v1/applications/fixture%2Fapp');
    assert.equal(calls[0][1].method, 'DELETE');
    if (scenario === 'reject') {
      assert.equal(cleared + collapsed + refreshed, 0); assert.equal(context.pending, true);
      assert.ok(notices.some(([, kind]) => kind === 'err'));
    } else {
      const applied = scenario === 'auto' || scenario === 'other_editor';
      assert.equal(context.pending, !applied); assert.equal(refreshed, 1);
      assert.equal(cleared, scenario === 'other_editor' ? 0 : 1); assert.equal(collapsed, cleared);
      assert.ok(notices.some(([text, kind]) => kind === 'ok' && /deleted/i.test(text) &&
        (applied ? /applied/i.test(text) : /Apply on Config/i.test(text))));
    }
  }
  const rows = [], context = {document: {getElementById: () => ({innerHTML: 'old'})},
    addRestrictedPathRow: (...args) => rows.push(args)};
  vm.createContext(context);
  include(context, '  function initRestrictedPathRows(', '  function clearRestrictedPathRows(');
  context.initRestrictedPathRows();
  assert.deepEqual(rows, [['', '']], 'new forms must not silently restrict HA API to LAN');
  for (const scenario of ['success', 'offline', 'rejected', 'malformed']) {
    const select = {value: 'home-assistant', innerHTML: ''};
    const help = {textContent: '', set innerHTML(value) {throw Error('profile help must use textContent')}};
    const catalog = {'home-assistant': {description: 'HA <test>', server_timeout_ms: 3600000,
      connect_timeout_ms: 5000, rate_limit_burst: 83, block_paths: ['/.git'],
      extra_blocked_methods: ['TRACE'], max_body_bytes: 0, block_multipart: false},
      'ha-mcp': {description: 'MCP', path_policy: {allow: ['/api/mcp', '/auth']}}};
    const guide = {document: {getElementById: id => {
      if (id === 'profile') return select;
      if (id === 'profile-help') return help;
      throw Error('profile choice must not mutate another form field: ' + id);
    }}, hdr: () => ({}), fetch: async path => {
      assert.equal(path, '/api/v1/profiles');
      if (scenario === 'offline') throw Error('fixture offline');
      return {ok: scenario !== 'rejected', status: scenario === 'rejected' ? 503 : 200,
        json: async () => scenario === 'malformed' ? [] : catalog};
    }};
    vm.createContext(guide);
    include(guide, '  let appProfilesCatalog =', '  async function loadProfilesDoc(');
    await guide.loadProfileSelect();
    assert.equal(select.value, 'home-assistant', 'loading metadata must preserve profile choice');
    if (scenario === 'success') {
      assert.match(help.textContent, /3600/); assert.match(help.textContent, /83/);
      assert.match(help.textContent, /HA <test>/); assert.match(help.textContent, /Companion/);
      assert.ok(!select.innerHTML.includes('HA <test>'), 'option labels escape metadata');
      select.value = 'ha-mcp'; select.onchange();
      assert.match(help.textContent, /\/api\/mcp/); assert.match(help.textContent, /404/);
    } else {
      assert.match(help.textContent, /unavailable/i);
    }
  }
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
