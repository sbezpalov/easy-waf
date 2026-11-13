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
const start = page.indexOf('  let aptStatusRevision = 0;');
const end = page.indexOf('  async function loadSystemServicesTable()', start);
assert.ok(start >= 0 && end > start, 'APT reconnect function not found');
const runID = '0123456789abcdef0123456789abcdef';
let status, calls = [], token = true, backendRun, mutations = 0, statusMode = 'ok';
let statusRequests = [];
const msg = {textContent: '', className: '', dataset: {}};
const context = {getTok: () => token, hdr: () => ({}),
  document: {getElementById: () => msg},
  fetch: async (path, options) => {
    statusRequests.push([path, options.method || 'GET']);
    if (statusMode === 'network') throw new Error('fixture status disconnect');
    return {ok: statusMode !== 'http', json: async () => {
      if (statusMode === 'json') throw new SyntaxError('fixture invalid JSON');
      return status;
    }};
  },
  encodeURIComponent,
  runAptStream: async (...args) => {
    calls.push(args);
    // The selected run can finish or be replaced after the status response.
    // The old endpoint starts a new upgrade when no active run remains.
    if (args[0] === '/api/v1/host/updates/upgrade/stream' && !backendRun) mutations++;
    return {exitCode: backendRun === runID ? 0 : -1, exitErr: ''};
  }};
vm.createContext(context);
vm.runInContext(page.slice(start, end), context);
(async () => {
  for (const selected of [null, runID, 'fedcba9876543210fedcba9876543210']) {
    calls = []; backendRun = selected;
    status = {active: true, action: 'upgrade', stream: true, run_id: runID};
    await context.tryAttachRunningAptUpgrade();
    assert.equal(mutations, 0, 'stale reconnect launched an unintended upgrade');
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], '/api/v1/host/updates/attach/stream?run_id=' + runID);
    assert.equal(calls[0][1].reconnect, true);
    assert.equal(calls[0][1].successMsg, 'Package operation finished.');
  }
  for (const action of ['update', 'upgrade', 'clean', 'autoremove', '__proto__']) {
    calls = []; backendRun = runID;
    status = {active: true, action, stream: false, run_id: runID};
    await context.tryAttachRunningAptUpgrade();
    assert.equal(calls.length, 1, 'known synchronous run lost safe observation');
    assert.equal(calls[0][0], '/api/v1/host/updates/attach/stream?run_id=' + runID);
  }
  for (const id of [undefined, '', 'bad-id', 'a'.repeat(31), 'A'.repeat(32), '../upgrade']) {
    calls = []; status = {active: true, run_id: id};
    await context.tryAttachRunningAptUpgrade();
    assert.equal(calls.length, 0, 'missing/invalid ID fell back to a mutation');
    assert.match(msg.textContent, /saved.*log/i);
  }
  calls = []; status = {active: true, run_id: runID, error: 'cannot verify apt action process'};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(calls.length, 0, 'unverified action triggered observation');
  assert.equal(msg.textContent, status.error);
  calls = []; status = {active: false};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(calls.length, 0, 'inactive action triggered an upgrade');
  status = {active: true};
  await context.tryAttachRunningAptUpgrade();
  status = {active: false};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(msg.textContent, '', 'finished action retained a running notice');
  status = {active: true};
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

  for (const value of [null, [], {}, {Active: false}, {active: null}, {active: 'false'}, {active: 0},
      {active: false, error: {}}, {active: true, exit_code: '0'},
      {active: true, stream: 1}, {active: true, run_id: null}]) {
    calls = []; statusRequests = []; status = value; msg.textContent = ''; msg.dataset = {};
    await context.tryAttachRunningAptUpgrade();
    assert.equal(calls.length, 0, 'invalid status started observation/mutation');
    assert.equal(msg.className, 'warn');
    assert.match(msg.textContent, /package status.*saved.*log/i);
    assert.deepEqual(statusRequests, [['/api/v1/host/updates/upgrade/status', 'GET']]);
  }
  for (const mode of ['http', 'json', 'network']) {
    statusMode = mode; calls = []; statusRequests = []; status = {active: true, run_id: runID};
    msg.textContent = ''; msg.dataset = {};
    await assert.doesNotReject(() => context.tryAttachRunningAptUpgrade());
    assert.equal(calls.length, 0, mode + ' failure triggered a fallback');
    assert.match(msg.textContent, /package status.*saved.*log/i);
    assert.equal(msg.className, 'warn');
    assert.deepEqual(statusRequests, [['/api/v1/host/updates/upgrade/status', 'GET']]);
  }
  statusMode = 'ok';
  for (const result of [
      {active: false, exit_code: -1, error: 'previous outcome unknown'},
      {active: false, exit_code: 100, error: ''}]) {
    calls = []; status = result; msg.textContent = ''; msg.dataset = {};
    await context.tryAttachRunningAptUpgrade();
    assert.equal(calls.length, 0);
    assert.equal(msg.className, 'warn', 'fresh failed/unknown result was hidden');
    assert.match(msg.textContent, result.error ? /previous outcome unknown/ : /100.*saved.*log/i);
  }
  status = {active: false};
  await context.tryAttachRunningAptUpgrade();
  assert.equal(msg.textContent, '', 'verified idle state retained a status-owned warning');
  for (const healthy of [false, true]) {
    let finishStatus;
    context.fetch = () => new Promise(resolve => {finishStatus = resolve});
    msg.textContent = ''; msg.dataset = {}; calls = [];
    const pendingStatus = context.tryAttachRunningAptUpgrade();
    msg.textContent = 'Newer operation result';
    finishStatus({ok: healthy, json: async () => ({active: true, run_id: runID})});
    await pendingStatus;
    assert.equal(msg.textContent, 'Newer operation result', 'late status erased a newer user result');
    assert.equal(calls.length, 0);
  }
  assert.equal(mutations, 0);

  // Latest status request wins even when both start/end with identical text.
  const replies = [];
  context.fetch = () => new Promise(resolve => replies.push(resolve));
  msg.textContent = ''; msg.dataset = {}; calls = [];
  const olderPoll = context.tryAttachRunningAptUpgrade();
  const newerPoll = context.tryAttachRunningAptUpgrade();
  replies[1]({ok: true, json: async () => ({active: false})});
  await newerPoll;
  replies[0]({ok: false});
  await olderPoll;
  assert.equal(msg.textContent, '', 'old failed poll replaced a newer verified idle result');
  assert.equal(calls.length, 0);

  const buttonStart = page.indexOf('  function setAptButtonsDisabled(');
  const buttonEnd = page.indexOf('  async function refreshAptPackageList()', buttonStart);
  vm.runInContext(page.slice(buttonStart, buttonEnd), context);
  const checkStart = page.indexOf("  document.getElementById('btn-sys-apt-check').onclick");
  const checkEnd = page.indexOf('\n  };', checkStart);
  assert.ok(buttonStart >= 0 && buttonEnd > buttonStart && checkStart >= 0 && checkEnd > checkStart);
  vm.runInContext(page.slice(checkStart, checkEnd + 6), context);
  const checkClick = msg.onclick;
  context.withBusy = async () => {}; // Exercise click ownership without issuing update.
  for (const begin of [() => context.setAptButtonsDisabled(true), () => checkClick()]) {
    let reply;
    context.fetch = () => new Promise(resolve => {reply = resolve});
    msg.textContent = ''; msg.dataset = {}; calls = [];
    const pending = context.tryAttachRunningAptUpgrade();
    await begin();
    msg.textContent = ''; // A newer action may finish with the very same text.
    reply({ok: true, json: async () => ({active: true, run_id: runID})});
    await pending;
    assert.equal(calls.length, 0, 'pre-action status started a stale observation');
    assert.equal(msg.textContent, '');
  }

  // Exercise the real stream request/error path too, without a browser or a
  // package executor. No reconnect error may trigger another endpoint.
  const streamStart = page.indexOf('  async function runAptStream(');
  const streamEnd = page.indexOf("  document.getElementById('btn-sys-apt-clean').onclick", streamStart);
  assert.ok(streamStart >= 0 && streamEnd > streamStart, 'APT stream function not found');
  vm.runInContext(page.slice(streamStart, streamEnd), context);
  const url = '/api/v1/host/updates/attach/stream?run_id=' + runID;
  context.apiMessage = async () => 'Observation unavailable';
  context.toast = () => { throw new Error('reconnect failure must not toast success'); };
  context.setAptButtonsDisabled = () => {};
  context.refreshAptPackageList = () => { throw new Error('unexpected package refresh'); };
  for (const mode of ['http', 'missing_body', 'network', 'reader']) {
    const requests = [];
    context.fetch = async (path, options) => {
      requests.push([path, options.method]);
      if (mode === 'network') throw new Error('fixture disconnect');
      return {ok: mode !== 'http', body: mode === 'missing_body' ? null : {}};
    };
    context.consumeAptStream = async () => { throw new Error('fixture read failure'); };
    const result = await context.runAptStream(url, {reconnect: true});
    assert.equal(result.exitCode, -1, mode + ' failure reported success');
    assert.ok(result.exitErr);
    assert.deepEqual(requests, [[url, 'POST']], mode + ' failure invoked a fallback');
    assert.equal(msg.className, 'warn');
    assert.match(msg.textContent, mode === 'http' || mode === 'missing_body'
      ? /Observation unavailable/ : /connection interrupted.*Refresh status/);
  }
})().catch(err => {console.error(err); process.exitCode = 1});
`
