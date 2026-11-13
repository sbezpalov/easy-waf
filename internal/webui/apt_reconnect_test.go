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

func TestAptReconnectRespectsOperationStatus(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute APT reconnect regression tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", aptReconnectTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("APT reconnect behavior: %v\n%s", err, output)
	}
}

const aptReconnectTest = `
const assert = require('node:assert/strict');
const vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  async function tryAttachRunningAptUpgrade()');
const end = page.indexOf('  async function loadSystemServicesTable()', start);
assert.ok(start >= 0 && end > start, 'APT reconnect function not found');
let status, calls = [], token = true;
const msg = {textContent: '', className: '', dataset: {}};
const context = {getTok: () => token, hdr: () => ({}),
  document: {getElementById: () => msg},
  fetch: async () => ({ok: true, json: async () => status}),
  runAptStream: async (...args) => calls.push(args)};
vm.createContext(context);
vm.runInContext(page.slice(start, end), context);
(async () => {
  for (const action of ['update', 'upgrade', 'clean', 'unknown', '__proto__', 'constructor']) {
    calls = [];
    status = {active: true, action, stream: false};
    await context.tryAttachRunningAptUpgrade();
    assert.equal(calls.length, 0, 'synchronous action triggered stream attach/upgrade');
    assert.match(msg.textContent, /is in progress/);
    assert.doesNotMatch(msg.textContent, /complete|finished|Reconnected/);
  }
  status = {active: true, error: 'cannot verify apt action process'};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(calls.length, 0, 'unverified action triggered a stream request');
  assert.equal(msg.textContent, status.error);
  for (const payload of [{active: true, action: 'autoremove', stream: true}, {active: true}]) {
    calls = []; status = payload;
    await context.tryAttachRunningAptUpgrade();
    assert.equal(calls.length, 1, 'stream/older broker lost reconnect support');
    assert.equal(calls[0][0], '/api/v1/host/updates/upgrade/stream');
    assert.equal(calls[0][1].reconnect, true);
    assert.equal(calls[0][1].successMsg, 'Package operation finished.');
    assert.equal(calls[0][1].successToast, 'Package operation complete');
  }
  calls = []; status = {active: false};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(calls.length, 0, 'inactive action triggered an upgrade');
  status = {active: true, action: 'update', stream: false};
  await context.tryAttachRunningAptUpgrade();
  status = {active: false};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(msg.textContent, '', 'finished action retained a running notice');
  status = {active: true, action: 'clean', stream: false};
  await context.tryAttachRunningAptUpgrade();
  msg.textContent = 'New user action result';
  status = {active: false};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(msg.textContent, 'New user action result', 'status erased a newer action result');
  status = {active: true, error: 'cannot verify process'};
  await context.tryAttachRunningAptUpgrade();
  status = {active: false, error: 'previous outcome unknown'};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(msg.textContent, status.error, 'resolved verification error hid the unknown result');
})().catch(err => {console.error(err); process.exitCode = 1});
`
