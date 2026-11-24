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

func TestStageASemanticShellAndTruthfulDashboard(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	required := []string{
		`class="skip-link" href="#main-content"`,
		`<header class="app-header">`,
		`<nav class="sidebar-nav" id="sidebar-nav" aria-label="Control plane">`,
		`<main class="app-content" id="main-content" tabindex="-1">`,
		`aria-expanded="false" aria-controls="app-sidebar"`,
		`a.setAttribute('aria-current', 'page')`,
		`Edge changes`,
		`Events &amp; audit`,
		`id="btn-dashboard-refresh" data-viewer-action="true"`,
		`id="dash-loaded-at" aria-live="polite">Not loaded`,
		`Saved preset modes:`,
		`LAPI reachable`,
		`Configured state`,
		`HAProxy backends (runtime)`,
		`/api/v1/edge/status`,
		`Saved and applied match`,
		`Apply relationship unknown`,
		`Process and backend health are separate`,
		`Unknown values are not replaced with zero.`,
		`:focus-visible`,
		`@media (prefers-reduced-motion: reduce)`,
		`minmax(min(100%, 15rem), 1fr)`,
		`.role-viewer main button:not([data-viewer-action="true"])`,
	}
	for _, want := range required {
		if !strings.Contains(html, want) {
			t.Errorf("Stage A UI missing %q", want)
		}
	}
	forbidden := []string{`Protected presets`, `● connected`, `○ disconnected`, `Applied state after a reload remains unknown without a persistent edge-status contract.`}
	for _, bad := range forbidden {
		if strings.Contains(html, bad) {
			t.Errorf("Stage A UI still contains misleading wording %q", bad)
		}
	}
}

func TestStageADashboardFailureDoesNotBecomeZero(t *testing.T) {
	runStageANodeTest(t, stageADashboardTest)
}

func TestStageASessionExpiryAndViewerWriteGate(t *testing.T) {
	runStageANodeTest(t, stageASessionTest)
}

func TestAPIMessagePreservesErrorSource(t *testing.T) {
	runStageANodeTest(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  async function apiMessage(');
const end = page.indexOf('  function confirmDialog(', start);
assert.ok(start >= 0 && end > start);
const context = vm.createContext({});
vm.runInContext(page.slice(start, end), context);
async function run() {
  const denied = 'CrowdSec LAPI denied access. Check the configured API key and permissions.';
  const cases = [
    [403, '', 'HTTP 403'],
    [403, 'Access forbidden', 'Access forbidden'],
    [403, '{"error":"read_only"}', 'Read-only account: ask an admin to make this change.'],
    [403, '{"error":"step_up_required"}', 'Cancelled: this operation needs your password.'],
    [502, JSON.stringify({error: denied}), denied]
  ];
  for (const [status, body, expected] of cases) {
    assert.equal(await context.apiMessage({status, text: async () => body}), expected);
  }
}
run().catch(error => {console.error(error); process.exitCode = 1});
`)
}

func runStageANodeTest(t *testing.T, script string) {
	t.Helper()
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
	cmd := exec.CommandContext(ctx, node, "-e", script)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Stage A UI interaction: %v\n%s", err, output)
	}
}

const stageADashboardTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  async function dashboardRequest(');
const end = page.indexOf("  document.getElementById('btn-settings-load').onclick", start);
assert.ok(start >= 0 && end > start, 'missing dashboard loader');

function makeElement(id) {
  const classes = new Set();
  return {id, textContent: '', innerHTML: '', dataset: {}, disabled: false,
    classList: {add: value => classes.add(value), remove: value => classes.delete(value),
      toggle: (value, on) => on ? classes.add(value) : classes.delete(value), contains: value => classes.has(value)}};
}

function response(body, status = 200) {
  return {ok: status >= 200 && status < 300, status,
    json: async () => body,
    text: async () => typeof body === 'string' ? body : JSON.stringify(body)};
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

async function scenario(mode) {
  const ids = ['dash-apps-stat', 'dash-certs-stat', 'dash-certs-sub', 'dash-cs-stat', 'dash-cs-sub',
    'dash-ipbl-stat', 'dash-req-rate', 'dash-active-sessions', 'dash-sec-line', 'dash-http-line',
    'dash-edge-state', 'dash-edge-generation', 'dash-edge-runtime', 'dash-revision-line', 'dash-last-apply', 'dash-backends', 'dash-services', 'dash-haproxy-table',
    'dash-haproxy-err', 'dash-attention-list', 'dash-status', 'dash-cert-warn', 'dash-sec-warn',
    'dash-http-warn', 'dash-loaded-at', 'view-app', 'dash-state-dir', 'dash-version', 'header-version',
    'btn-dashboard-refresh'];
  const elements = Object.fromEntries(ids.map(id => [id, makeElement(id)]));
  const successful = {
    '/api/v1/status': {version: 'fixture'},
    '/api/v1/edge/status': {saved_generation: 7, applied_generation: 7, pending: false,
      last_apply: {outcome: 'success', at: '2026-11-17T10:00:00Z', revision_sha: 'abcdef0123456789'},
      runtime: {state: 'known', checked_at: '2026-11-17T10:01:00Z', revision_sha: 'abcdef0123456789'}},
    '/api/v1/applications': [],
    '/api/v1/certificates/summary': {valid: 0, expiring_soon: 0, expired: 0, failed: 0, total: 0, certificates: []},
    '/api/v1/revisions?limit=30': [],
    '/api/v1/integrations/crowdsec': {reachable: true, last_message: 'probe ok'},
    '/api/v1/integrations/crowdsec/decisions': null,
    '/api/v1/ipbl/local': [],
    '/api/v1/ipbl/sources': [],
    '/api/v1/system/services': {services: []},
    '/api/v1/stats/summary': {req_rate: 0, active_sessions: 0},
    '/api/v1/stats/haproxy': {backends: []}
  };
  let panel = 'dashboard';
  let poll;
  let holdSummary;
  let heldCalls = 0;
  let pollRuntimeError = false;
  let disconnected = mode === 'offline';
  let clock = '14:00:00';
  let simulateTimeout = mode === 'timeout';
  let timeoutID = 0;
  const timeouts = new Map();
  const timedOutSignals = [];
  function waitForAbort(signal) {
    timedOutSignals.push(signal);
    return new Promise((_, reject) => {
      signal.addEventListener('abort', () => reject(Error('fixture aborted')), {once: true});
    });
  }
  const context = {console, document: {getElementById: id => elements[id]}, sessionExpired: false,
    Date: class extends Date { static now() { return Date.parse('2026-01-01T' + clock + 'Z'); } },
    fetch: async (path, options) => {
      if (pollRuntimeError && path === '/api/v1/stats/haproxy') {
        return response({backends: null, error: 'Runtime poll unavailable'});
      }
      if (simulateTimeout && path === '/api/v1/certificates/summary') return waitForAbort(options.signal);
      if (simulateTimeout && path === '/api/v1/stats/haproxy') {
        return {...response(null), json: () => waitForAbort(options.signal)};
      }
      if (holdSummary && path === '/api/v1/stats/summary') {
        heldCalls++;
        holdSummary.signal = options.signal;
        return holdSummary.promise;
      }
      if (disconnected) throw Error('fixture offline');
      if (mode === 'decisions_denied' && path === '/api/v1/integrations/crowdsec/decisions') {
        return response({error: 'CrowdSec LAPI denied access. Check the configured API key and permissions.'}, 502);
      }
      if ((mode === 'stats_error' || mode === 'summary_error') && path === '/api/v1/stats/summary') {
        return response({req_rate: 0, active_sessions: 0, error: 'Stats socket unavailable'});
      }
      if ((mode === 'stats_error' || mode === 'runtime_error') && path === '/api/v1/stats/haproxy') {
        return response({backends: null, error: 'Stats socket unavailable'});
      }
      if (mode === 'summary_error' && path === '/api/v1/stats/haproxy') {
        return response({backends: [{name: 'be_fixture', status: 'UP', health: 'healthy', sessions_cur: 2}]});
      }
      return response(successful[path]);
    },
    hdr: () => ({}), panelFromHash: () => panel, AbortController,
    setInterval: callback => { poll = callback; return 1; },
    clearInterval: () => { poll = null; },
    esc: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;'),
    statusBadge: (label, tone) => '<badge data-tone="' + tone + '">' + label + '</badge>',
    alertView: (tone, title, message) => '<alert data-tone="' + tone + '">' + title + ': ' + message + '</alert>',
    stateView: (state, message) => '<state data-state="' + state + '">' + message + '</state>',
    renderApplicationVersion: value => { elements['dash-version'].textContent = value || 'Unknown'; },
    renderPersistentEdgeStatus: status => status != null,
    formatHostTime: value => typeof value === 'number' ? new Date(value).toISOString().slice(11, 19) : value,
    apiMessage: async r => (await r.json()).error, shortSha: value => String(value || '').slice(0, 8),
    withBusy: async (_button, fn) => fn(),
    setTimeout: (callback, delay) => { timeouts.set(++timeoutID, {callback, delay}); return timeoutID; },
    clearTimeout: id => { timeouts.delete(id); }};
  vm.createContext(context);
  const countStart = page.indexOf('  function decisionsCount(');
  const countEnd = page.indexOf('  let dashStatsTimer', countStart);
  const timerEnd = page.indexOf('  const AUDIT_PAGE', countEnd);
  vm.runInContext(page.slice(countStart, countEnd), context);
  vm.runInContext(page.slice(countEnd, timerEnd), context);
  vm.runInContext(page.slice(start, end), context);
  const refresh = context.loadDashboard();
  if (mode === 'timeout') {
    await new Promise(setImmediate);
    assert.equal(timedOutSignals.length, 2, 'slow headers and slow body must run in parallel');
    assert.equal(timeouts.size, 2, 'only the stalled requests should still have timers');
    for (const {callback, delay} of timeouts.values()) {
      assert.equal(delay, 10000);
      callback();
    }
    await refresh;
    assert.equal(timeouts.size, 0);
    assert.ok(timedOutSignals.every(signal => signal.aborted));
    assert.equal(elements['dash-apps-stat'].textContent, '0 / 0');
    assert.equal(elements['dash-req-rate'].textContent, '0.0');
    assert.match(elements['dash-haproxy-table'].innerHTML, /data-state="offline"/);
    assert.match(elements['dash-attention-list'].innerHTML, /Certificate summary \(timed out\)/);
    assert.match(elements['dash-attention-list'].innerHTML, /HAProxy runtime \(timed out\)/);
    assert.equal(elements['dash-status'].dataset.state, 'error');
    assert.equal(typeof poll, 'function', 'periodic refresh must resume after a timeout');
    simulateTimeout = false;
    await poll();
    assert.match(elements['dash-haproxy-table'].innerHTML, /data-state="empty"/);
    assert.equal(elements['dash-haproxy-err'].textContent, '');
    assert.match(elements['dash-attention-list'].innerHTML, /Certificate summary \(timed out\)/);
    assert.doesNotMatch(elements['dash-attention-list'].innerHTML, /HAProxy runtime \(timed out\)/);
    assert.equal(elements['dash-status'].dataset.state, 'error');
    assert.equal(timeouts.size, 0);
    return;
  }
  await refresh;
  if (mode === 'traffic_poll') {
    assert.equal(elements['dash-loaded-at'].textContent, 'Loaded at 14:00:00');
    clock = '14:00:10';
    pollRuntimeError = true;
    await poll();
    assert.equal(elements['dash-status'].dataset.state, 'error');
    assert.match(elements['dash-attention-list'].innerHTML, /HAProxy runtime \(Runtime poll unavailable\)/);
    assert.equal(elements['dash-loaded-at'].textContent, 'Partial data at 14:00:00');
    clock = '14:00:20';
    pollRuntimeError = false;
    await poll();
    assert.equal(elements['dash-status'].dataset.state, 'ready');
    assert.doesNotMatch(elements['dash-attention-list'].innerHTML, /HAProxy runtime \(Runtime poll unavailable\)/);
    assert.equal(elements['dash-loaded-at'].textContent, 'Loaded at 14:00:00');
    return;
  }
  if (mode === 'overlap') {
    const oldSummary = holdSummary = deferred();
    const oldPoll = poll();
    void poll();
    assert.equal(heldCalls, 1, 'poll must skip a tick while the previous read is pending');
    holdSummary = null;
    successful['/api/v1/stats/summary'] = {req_rate: 9, active_sessions: 2};
    await context.loadDashboard();
    assert.equal(oldSummary.signal.aborted, true, 'manual refresh must abort the old poll');
    oldSummary.resolve(response({req_rate: 99, active_sessions: 99}));
    await oldPoll;
    assert.equal(elements['dash-req-rate'].textContent, '9.0');
    assert.equal(elements['dash-active-sessions'].textContent, '2');

    const unfinished = holdSummary = deferred();
    const pendingPoll = poll();
    panel = 'apps';
    context.stopDashStatsTimer();
    assert.equal(poll, null);
    assert.equal(unfinished.signal.aborted, true, 'leaving the dashboard must abort the active read');
    unfinished.resolve(response({req_rate: 99, active_sessions: 99}));
    await pendingPoll;
    assert.notEqual(elements['dash-req-rate'].textContent, '99.0');
    return;
  }
  if (mode === 'offline') {
    assert.equal(elements['dash-apps-stat'].textContent, 'Unknown');
    assert.equal(elements['dash-ipbl-stat'].textContent, 'Unknown');
    assert.equal(elements['dash-req-rate'].textContent, 'Unknown');
    assert.equal(elements['dash-loaded-at'].textContent, 'Not loaded');
    assert.equal(elements['dash-status'].dataset.state, 'offline');
    assert.match(elements['dash-attention-list'].innerHTML, /incomplete/);
    assert.doesNotMatch(elements['dash-ipbl-stat'].textContent, /0/);
    disconnected = false;
    clock = '14:00:10';
    await poll();
    assert.equal(elements['dash-status'].dataset.state, 'error');
    assert.equal(elements['dash-loaded-at'].textContent, 'HAProxy loaded at 14:00:10');
    assert.equal(elements['dash-apps-stat'].textContent, 'Unknown');
    assert.equal(elements['dash-req-rate'].textContent, '0.0');
  } else {
    assert.equal(elements['dash-apps-stat'].textContent, '0 / 0');
    assert.equal(elements['dash-ipbl-stat'].textContent, '0 · 0');
    assert.match(elements['dash-cs-stat'].innerHTML, /LAPI reachable/);
    assert.match(elements['dash-edge-state'].innerHTML, /Saved and applied match/);
    assert.match(elements['dash-edge-runtime'].textContent, /Process and backend health are separate/);
    assert.match(elements['dash-loaded-at'].textContent, mode === 'success' ? /^Loaded at / : /^Partial data at /);
    if (mode === 'decisions_denied') {
      assert.match(elements['dash-cs-stat'].innerHTML, /warning.*LAPI reachable/);
      assert.match(elements['dash-cs-sub'].textContent, /Decisions unavailable/);
      assert.match(elements['dash-attention-list'].innerHTML, /configured API key and permissions/);
      assert.equal(elements['dash-status'].dataset.state, 'error');
    } else if (mode === 'success') {
      assert.match(elements['dash-cs-sub'].textContent, /sample decisions: 0/);
      assert.equal(elements['dash-status'].dataset.state, 'ready');
      assert.equal(elements['dash-req-rate'].textContent, '0.0');
      assert.equal(elements['dash-active-sessions'].textContent, '0');
      assert.match(elements['dash-haproxy-table'].innerHTML, /data-state="empty"/);
    } else {
      const summaryFailed = mode !== 'runtime_error';
      const runtimeFailed = mode !== 'summary_error';
      assert.equal(elements['dash-status'].dataset.state, 'error');
      assert.equal(elements['dash-req-rate'].textContent, summaryFailed ? 'Unknown' : '0.0');
      assert.equal(elements['dash-active-sessions'].textContent, summaryFailed ? 'Unknown' : '0');
      assert.match(elements['dash-haproxy-table'].innerHTML, runtimeFailed ? /data-state="offline"/ : /be_fixture/);
      assert.match(elements['dash-haproxy-err'].textContent, /Stats socket unavailable/);
      assert.match(elements['dash-attention-list'].innerHTML, /Dashboard data is incomplete/);
    }
  }
}
(async () => {
  for (const mode of ['offline', 'success', 'decisions_denied', 'stats_error', 'summary_error', 'runtime_error', 'overlap', 'timeout', 'traffic_poll']) {
    await scenario(mode);
  }
})()
  .catch(error => {console.error(error); process.exitCode = 1});
`

const stageASessionTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  const nativeFetch = window.fetch.bind(window);');
const end = page.indexOf('  const HASH_TO_PANEL = {', start);
assert.ok(start >= 0 && end > start, 'missing centralized request handling');

async function sessionScenario() {
  let token = 'fixture-token', nativeCalls = 0, loginShown = false;
  const elements = {'login-err': {textContent: ''}, 'login-pass': {value: 'secret', focus() {this.focused = true}}};
  const classList = {remove() {}, add() {}, contains() {return false}};
  const context = {Request, Response, Headers, URL, console,
    window: {location: {origin: 'https://fixture'}, fetch: async () => { nativeCalls++; return new Response('{}', {status: 401}); }},
    document: {body: {classList}, getElementById: id => elements[id]},
    getTok: () => token, setTok: value => {token = value}, hdr: () => ({}),
    stopDashStatsTimer() {}, stopAuditRefreshTimer() {}, closeMobileNav() {},
    show: (id, on) => { if (id === 'view-login' && on) loginShown = true }};
  vm.createContext(context);
  vm.runInContext(page.slice(start, end), context);
  const result = await context.window.fetch('/api/v1/applications', {headers: {Authorization: 'Bearer fixture'}});
  assert.equal(result.status, 401);
  assert.equal(nativeCalls, 1);
  assert.equal(token, '');
  assert.equal(loginShown, true);
  assert.match(elements['login-err'].textContent, /session expired/i);
  assert.equal(elements['login-pass'].focused, true);
}

async function viewerScenario() {
  let token = 'fixture-token', nativeCalls = 0;
  const context = {Request, Response, Headers, URL, console,
    window: {location: {origin: 'https://fixture'}, fetch: async () => { nativeCalls++; return new Response('{}', {status: 200}); }},
    document: {body: {classList: {remove() {}}}, getElementById: () => null},
    getTok: () => token, setTok: value => {token = value}, hdr: () => ({}),
    stopDashStatsTimer() {}, stopAuditRefreshTimer() {}, closeMobileNav() {}, show() {}};
  vm.createContext(context);
  vm.runInContext(page.slice(start, end), context);
  vm.runInContext("currentRole = 'viewer'", context);
  const denied = await context.window.fetch('/api/v1/settings', {method: 'PATCH'});
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error, 'read_only');
  assert.equal(nativeCalls, 0, 'viewer write must not reach the network');
  assert.equal((await context.window.fetch('/api/v1/status')).status, 200);
  assert.equal((await context.window.fetch('/api/v1/auth/logout', {method: 'POST'})).status, 200);
  assert.equal(nativeCalls, 2, 'read and self-service logout remain available');
}
(async () => { await sessionScenario(); await viewerScenario(); })()
  .catch(error => {console.error(error); process.exitCode = 1});
`
