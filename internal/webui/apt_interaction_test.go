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

func TestAptInteractionOwnership(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute APT interaction regression tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{
		"repeated_reconnect", "local_stream_blocks_poll", "stream_blocks_actions",
		"check_blocks_stream", "clean_blocks_stream", "slow_error_keeps_ownership",
		"failure_releases_ownership", "package_list_owns_interaction", "check_empty_or_failed", "disk_cannot_enable_clean",
		"small_cache_stays_disabled", "pending_poll_then_action", "idle_package_list",
		"idle_list_cannot_overwrite_check", "saved_log_cannot_overwrite_stream",
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "-e", aptInteractionTest, scenario)
			cmd.Stdin = bytes.NewReader(page)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("APT interaction ownership: %v\n%s", err, output)
			}
		})
	}
}

const aptInteractionTest = `
const assert = require('node:assert/strict');
const vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const scenario = process.argv[1];
const timer = setTimeout(() => {console.error('unjoined scenario: ' + scenario); process.exit(1)}, 5000);
const flush = () => new Promise(setImmediate);
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => {resolve = yes; reject = no});
  return {promise, resolve, reject};
};
function feed() {
  const queue = [], readers = [];
  const put = value => readers.length ? readers.shift().resolve(value) : queue.push(value);
  return {body: {getReader: () => ({read: () => {
    if (queue.length) return Promise.resolve(queue.shift());
    const next = deferred(); readers.push(next); return next.promise;
  }, cancel: async () => {}, releaseLock: () => {}})}, line: text => put({value: new TextEncoder().encode(JSON.stringify({type: 'line', data: text}) + '\n'), done: false}),
    end: () => {
      put({value: new TextEncoder().encode('{"type":"exit","code":0}\n'), done: false});
      put({done: true});
    }};
}
const ids = ['btn-sys-apt-check', 'btn-sys-apt-upgrade', 'btn-sys-apt-autoremove', 'btn-sys-apt-clean'];
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {textContent: '', disabled: false,
    className: '', dataset: {}, style: {}, scrollHeight: 0, scrollTop: 0, clientHeight: 0});
  return elements.get(id);
};
const msg = element('sys-apt-msg'), out = element('sys-apt-output');
const packages = element('sys-apt-packages');
const requests = [], notices = [];
const runID = '0123456789abcdef0123456789abcdef';
const url = '/api/v1/host/updates/upgrade/stream';
const checkURL = '/api/v1/host/updates/update/stream';
const json = value => ({ok: true, json: async () => value});
let source = feed();
let request = async path => {
  if (path.endsWith('/status')) return json({active: true, run_id: runID});
  if (path.includes('/stream')) return {ok: true, body: source.body};
  if (path.endsWith('/disk')) return json({mounts: [], cache_bytes: 8 << 20});
  return json({output: 'Package list', freed_bytes: 0});
};
const context = {getTok: () => true, hdr: () => ({}), encodeURIComponent, TextDecoder,
  document: {getElementById: element},
  fetch: async (path, opts) => {requests.push([path, opts && opts.method || 'GET']); return request(path, opts)},
  toast: (...args) => notices.push(args), apiMessage: async () => 'Request rejected',
  confirmDialog: async () => true, esc: text => text};
vm.createContext(context);
function include(from, until) {
  const start = page.indexOf(from), end = page.indexOf(until, start);
  assert.ok(start >= 0 && end > start, 'embedded function region missing: ' + from);
  vm.runInContext(page.slice(start, end), context);
}
include('  async function withBusy(', '  function tableState(');
include('  function formatBytes(', '  let aptStatusRevision = 0;');
include('  let aptStatusRevision = 0;', '  async function loadSystemServicesTable(');
include("  document.getElementById('btn-sys-apt-check').onclick", "  document.getElementById('btn-sys-reboot').onclick");
const disabled = expected => ids.forEach(id => assert.equal(element(id).disabled, expected, id + ' ownership state'));
const finish = async pending => {source.end(); await pending; await flush(); disabled(false)};
const cases = {
  async repeated_reconnect() {
    const first = context.tryAttachRunningAptUpgrade(); await flush();
    const second = context.tryAttachRunningAptUpgrade(); await flush();
    assert.equal(requests.filter(([path]) => path.includes('/stream')).length, 1, 'tab reentry opened another stream');
    assert.equal(requests.filter(([path]) => path.endsWith('/status')).length, 1, 'live owner was polled again');
    disabled(true); source.line('One log line'); await flush();
    assert.equal(out.textContent, 'One log line');
    source.end(); await Promise.all([first, second]); disabled(false);
  },
  async local_stream_blocks_poll() {
    const pending = context.runAptStream(url); await flush();
    const poll = context.tryAttachRunningAptUpgrade(); await flush();
    assert.deepEqual(requests, [[url, 'POST']], 'local stream acquired a competing observer');
    await finish(pending); await poll;
  },
  async stream_blocks_actions() {
    const pending = context.runAptStream(url, {startMsg: 'Upgrade running'}); await flush();
    await element(ids[0]).onclick(); await element(ids[3]).onclick();
    assert.deepEqual(requests, [[url, 'POST']], 'competing click reached a package endpoint');
    assert.equal(msg.textContent, 'Upgrade running'); disabled(true);
    await finish(pending);
  },
  async check_blocks_stream() {
    const fullList = Array.from({length: 200}, (_, index) => 'package-' + index + '/stable 1.1 amd64').join('\n');
    const original = request;
    request = path => path === '/api/v1/host/updates' ? json({output: fullList}) : original(path);
    const checking = element(ids[0]).onclick(); await flush(); disabled(true);
    assert.equal(msg.textContent, 'Checking for updates…');
    source.line('Refreshing indexes'); await flush();
    assert.equal(out.textContent, 'Refreshing indexes');
    await context.runAptStream(url);
    assert.deepEqual(requests, [[checkURL, 'POST']], 'check overlapped a stream or fetched before completion');
    await finish(checking);
    assert.deepEqual(requests, [[checkURL, 'POST'], ['/api/v1/host/updates', 'GET']]);
    assert.equal(msg.textContent, 'Package indexes refreshed.');
    assert.equal(packages.textContent, fullList);
    assert.equal(out.textContent, 'Refreshing indexes');
  },
  async clean_blocks_stream() {
    const response = deferred(), original = request;
    request = path => path.endsWith('/clean') ? response.promise : original(path);
    const cleaning = element(ids[3]).onclick(); await flush(); disabled(true);
    const competing = context.runAptStream(url); await flush();
    assert.deepEqual(requests, [['/api/v1/host/updates/clean', 'POST']], 'cache clean overlapped a stream');
    await competing;
    response.resolve(json({freed_bytes: 0})); await cleaning; disabled(false);
    assert.equal(msg.textContent, 'Apt cache cleaned.');
  },
  async slow_error_keeps_ownership() {
    const detail = deferred();
    request = async () => ({ok: false}); context.apiMessage = () => detail.promise;
    const pending = context.runAptStream(url); await flush(); disabled(true);
    await context.runAptStream(url);
    assert.deepEqual(requests, [[url, 'POST']], 'error parsing released ownership prematurely');
    detail.resolve('Observation rejected');
    const result = await pending; disabled(false);
    assert.equal(result.exitCode, -1); assert.equal(msg.textContent, 'Observation rejected');
  },
  async failure_releases_ownership() {
    for (const mode of ['network', 'reader', 'http', 'check', 'clean']) {
      requests.length = 0;
      request = async () => {
        if (mode === 'network' || mode === 'check' || mode === 'clean') throw new Error('fixture disconnect');
        if (mode === 'http') return {ok: false};
        return {ok: true, body: {getReader: () => ({read: async () => {throw new Error('fixture reader')},
          cancel: async () => {}, releaseLock: () => {}})}};
      };
      if (mode === 'clean') {
        await assert.rejects(() => element(ids[3]).onclick());
      } else if (mode === 'check') {
        await element(ids[0]).onclick();
        assert.match(msg.textContent, /Stream interrupted/);
      } else {
        const result = await context.runAptStream(url, {reconnect: true});
        assert.equal(result.exitCode, -1);
      }
      disabled(false); await flush(); requests.length = 0;
      request = async () => ({ok: false});
      await context.runAptStream(url, {reconnect: true});
      assert.deepEqual(requests, [[url, 'POST']], mode + ' failure leaked ownership'); disabled(false);
    }
  },
  async package_list_owns_interaction() {
    const list = deferred(), original = request;
    request = path => path === '/api/v1/host/updates' ? list.promise : original(path);
    const first = context.runAptStream(url); await flush(); source.line('Upgrade log'); source.end();
    await flush();
    disabled(true);
    await context.runAptStream(url);
    assert.deepEqual(requests, [[url, 'POST'], ['/api/v1/host/updates', 'GET']]);
    list.resolve(json({output: 'Package list'})); await first;
    assert.equal(out.textContent, 'Upgrade log');
    assert.equal(packages.textContent, 'Package list');
    disabled(false);
  },
  async check_empty_or_failed() {
    const original = request;
    for (const [response, expected] of [
      [json({}), 'No package updates available.'],
      [{ok: false}, 'Could not load available packages. Run Check for updates to retry.']
    ]) {
      source = feed();
      request = path => path === '/api/v1/host/updates' ? response : original(path);
      const checking = element(ids[0]).onclick(); await flush();
      await finish(checking);
      assert.equal(packages.textContent, expected);
    }
  },
  async idle_package_list() {
    const original = request;
    request = path => path.endsWith('/status') ? json({active: false}) : original(path);
    await context.tryAttachRunningAptUpgrade();
    assert.deepEqual(requests, [['/api/v1/host/updates/upgrade/status', 'GET'], ['/api/v1/host/updates', 'GET']]);
    assert.equal(packages.textContent, 'Package list');
    disabled(false);
  },
  async idle_list_cannot_overwrite_check() {
    const list = deferred(), original = request;
    let firstList = true;
    request = path => {
      if (path.endsWith('/status')) return json({active: false});
      if (path === '/api/v1/host/updates' && firstList) {
        firstList = false;
        return list.promise;
      }
      return original(path);
    };
    const idle = context.tryAttachRunningAptUpgrade(); await flush();
    const checking = element(ids[0]).onclick(); await flush();
    list.resolve(json({output: 'Stale list'})); await idle;
    assert.match(packages.textContent, /after a successful check/);
    await finish(checking);
    assert.equal(packages.textContent, 'Package list');
  },
  async saved_log_cannot_overwrite_stream() {
    const log = deferred(), original = request;
    request = path => path.endsWith('/log') ? {ok: true, text: () => log.promise} : original(path);
    const savedButton = element('btn-sys-apt-last-log');
    const saved = savedButton.onclick(); await flush();
    const checking = element(ids[0]).onclick(); await flush();
    assert.equal(savedButton.disabled, true);
    source.line('Live progress'); await flush();
    log.resolve('Older saved log'); await saved;
    assert.equal(out.textContent, 'Live progress');
    await finish(checking);
    assert.equal(savedButton.disabled, false);
  },
  async disk_cannot_enable_clean() {
    const disk = deferred(), original = request;
    request = path => path.endsWith('/disk') ? disk.promise : original(path);
    const loading = context.loadHostDiskPanel();
    const pending = context.runAptStream(url); await flush(); disabled(true);
    disk.resolve(json({mounts: [], cache_bytes: 8 << 20})); await loading;
    disabled(true); await finish(pending);
  },
  async small_cache_stays_disabled() {
    const original = request;
    request = path => path.endsWith('/disk') ? json({mounts: [], cache_bytes: 0}) : original(path);
    await context.loadHostDiskPanel();
    assert.equal(element(ids[3]).disabled, true);
    const pending = context.runAptStream(url); await flush(); disabled(true);
    source.end(); await pending;
    ids.slice(0, 3).forEach(id => assert.equal(element(id).disabled, false));
    assert.equal(element(ids[3]).disabled, true, 'owner release erased the known cache condition');
  },
  async pending_poll_then_action() {
    const status = deferred(), original = request;
    request = path => path.endsWith('/status') ? status.promise : original(path);
    const poll = context.tryAttachRunningAptUpgrade();
    const pending = context.runAptStream(url, {startMsg: 'New action running'}); await flush();
    status.resolve(json({active: true, run_id: runID})); await poll;
    assert.equal(requests.filter(([path]) => path.includes('/stream')).length, 1);
    assert.equal(msg.textContent, 'New action running');
    disabled(true); await finish(pending);
  }
};
(async () => {
  assert.ok(cases[scenario], 'unknown scenario');
  await cases[scenario]();
  clearTimeout(timer);
})().catch(err => {console.error(err); process.exit(1)});
`
