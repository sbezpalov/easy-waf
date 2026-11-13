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

// Node is optional for Go-only development. When available, execute the actual
// inline functions with a controlled clock/DOM instead of matching source text.
func TestHostRollbackCountdown(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute UI countdown regression tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", rollbackCountdownTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rollback countdown behavior: %v\n%s", err, output)
	}
}

const rollbackCountdownTest = `
const assert = require('node:assert/strict');
const vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  function updateHostRollbackApplyButtons()');
const end = page.indexOf('  async function loadSystemTab()', start);
assert.ok(start >= 0 && end > start, 'countdown functions not found');
let now = Date.now(), nextTimer = 0;
const timers = new Map(), notices = [], elements = new Map();
const state = {timer: null};
const element = id => {
  if (!elements.has(id)) elements.set(id, {hidden: true, classList: {
    add: () => {element(id).hidden = true}, remove: () => {element(id).hidden = false}
  }});
  return elements.get(id);
};
let payload;
const context = {assert, hostRollback: state, Date: class extends Date {static now() {return now}},
  document: {getElementById: element}, setInterval: fn => {timers.set(++nextTimer, fn); return nextTimer},
  clearInterval: id => timers.delete(id), toast: (...args) => notices.push(args),
  confirmDialog: async () => true, hdr: () => ({}),
  fetch: async () => ({ok: true, json: async () => payload})};
vm.createContext(context);
vm.runInContext(page.slice(start, end), context);
const show = expiry => context.showHostRollbackBanner('netplan', 'test-token', expiry, '/commit');
for (const expiry of [new Date(now - 1000).toISOString(), 'invalid-date']) {
  notices.length = 0;
  const shown = show(expiry);
  assert.equal(timers.size, 0, 'expired response restarted countdown');
  assert.equal(shown, false);
  assert.equal(state.token, null);
  assert.equal(notices.length, 1);
}
notices.length = 0;
assert.equal(show(new Date(now + 90000).toISOString()), true);
assert.equal(element('host-rollback-countdown').textContent, '90');
assert.equal(element('btn-net-netplan-apply').disabled, true);
assert.equal(timers.size, 1);
now += 90000;
for (const tick of [...timers.values()]) tick();
assert.equal(timers.size, 0);
assert.equal(state.token, null);
assert.equal(element('btn-net-netplan-apply').disabled, false);
assert.equal(notices.length, 1);
notices.length = 0;
payload = {token: 'test-token', expires_at: new Date(now - 1000).toISOString()};
context.applyHostWithRollback({kind: 'netplan', applyUrl: '/apply', commitUrl: '/commit', body: {}, msgEl: {}})
  .then(() => {
    assert.equal(timers.size, 0);
    assert.equal(notices.length, 1, 'expired response advertised successful confirmation window');
  }).catch(err => {console.error(err); process.exitCode = 1});
`
