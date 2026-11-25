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

// Both Network and Settings can start a timed firewall change.
func TestHostRollbackConfirmationIsOutsideTabPanels(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	main := bytes.Index(page, []byte(`id="main-content"`))
	firstPanel := bytes.Index(page, []byte(`class="tab-panel`))
	if main < 0 || firstPanel <= main {
		t.Fatal("missing shared main content before the first tab")
	}
	for _, id := range []string{"host-rollback-banner", "btn-host-rollback-keep"} {
		attr := []byte(`id="` + id + `"`)
		if !bytes.Contains(page[main:firstPanel], attr) || bytes.Count(page, attr) != 1 {
			t.Fatalf("%s must appear once in shared main content", id)
		}
	}
}

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
const zabbixStart = page.indexOf('  let zabbixFirewallRead = 0;');
const zabbixEnd = page.indexOf('  function loadSettingsTab()', zabbixStart);
assert.ok(zabbixStart >= 0 && zabbixEnd > zabbixStart, 'Zabbix status loader not found');
let now = Date.now(), nextTimer = 0;
const timers = new Map(), timeouts = new Map(), notices = [], elements = new Map(), storage = new Map();
const state = {timer: null, statusRetry: null, polling: false, statusUnknown: true, statusWarned: false, expiryNotified: false};
const element = id => {
  if (!elements.has(id)) elements.set(id, {hidden: true, classList: {
    add: () => {element(id).hidden = true}, remove: () => {element(id).hidden = false},
    toggle: (_, force) => {element(id).hidden = !!force},
    contains: cls => id === 'tab-settings' && cls === 'active'
  }});
  return elements.get(id);
};
let applyPayload, statusPayload = {changes: []}, networkReloads = 0, busy = false;
let firewall = {}, firewallReads = 0;
const context = {assert, hostRollback: state, Date: class extends Date {static now() {return now}},
  currentRole: 'admin',
  HOST_ROLLBACK_STORAGE_KEY: 'test-host-rollback',
  document: {getElementById: element}, setInterval: fn => {timers.set(++nextTimer, fn); return nextTimer},
  clearInterval: id => timers.delete(id), toast: (...args) => notices.push(args),
  setTimeout: fn => {timeouts.set(++nextTimer, fn); return nextTimer}, clearTimeout: id => timeouts.delete(id),
  confirmDialog: async () => true, hdr: () => ({}), apiMessage: async () => 'failed',
  sessionStorage: {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
  loadNetworkTab: async () => {networkReloads++},
  fetch: async (url, options) => {
    if (url === '/api/v1/host/firewall') {
      firewallReads++;
      assert.equal(options.cache, 'no-store');
      return {ok: true, json: async () => firewall};
    }
    if (url === '/api/v1/host/changes/pending' && busy) {
      return {ok: false, status: 503, headers: {get: name => name === 'Retry-After' ? '1' : null}};
    }
    return {ok: true, json: async () => url === '/api/v1/host/changes/pending' ? statusPayload : applyPayload};
  }};
vm.createContext(context);
vm.runInContext(page.slice(zabbixStart, zabbixEnd), context);
vm.runInContext(page.slice(start, end), context);
const operationID = 'a'.repeat(64);
const capability = {kind: 'netplan', token: 'test-token', operation_id: operationID,
  expires_at: new Date(now + 90000).toISOString(), commit_url: '/commit'};
statusPayload = {changes: [{kind: 'netplan', operation_id: operationID, phase: 'pending',
  expires_at: capability.expires_at, confirmable: true}]};
context.saveHostRollbackCapability(capability);
(async () => {
  busy = true;
  await context.refreshHostRollbackStatus();
  assert.equal(state.statusUnknown, true, 'busy response was treated as settled');
  assert.equal(element('btn-net-netplan-apply').disabled, true);
  assert.equal(notices.length, 0, 'transient contention showed a connection warning');
  assert.equal(timeouts.size, 1);
  busy = false;
  [...timeouts.values()][0]();
  await new Promise(setImmediate);
  assert.equal(state.statusUnknown, false);
  assert.equal(timeouts.size, 0);
  assert.equal(state.token, 'test-token', 'same-tab reload lost commit capability');
  assert.match(element('host-rollback-message').textContent, /90s/);
  assert.equal(element('btn-host-rollback-keep').hidden, false);
  assert.equal(element('btn-net-netplan-apply').disabled, true);

  context.clearHostRollbackCapability();
  await context.refreshHostRollbackStatus();
  assert.equal(state.token, null, 'another tab obtained commit capability from status');
  assert.equal(element('host-rollback-banner').hidden, false, 'other tab lost server pending state');
  assert.equal(element('btn-host-rollback-keep').hidden, true, 'other tab can keep changes');
  assert.match(element('host-rollback-message').textContent, /only in the tab that started/);

  context.saveHostRollbackCapability(capability);
  state.polling = true;
  context.showHostRollbackBanner(statusPayload.changes[0], capability);
  now += 90000;
  for (const tick of [...timers.values()]) tick();
  for (const tick of [...timers.values()]) tick();
  state.polling = false;
  assert.equal(state.phase, 'expired');
  assert.equal(state.token, null);
  assert.equal(element('host-rollback-banner').hidden, false, 'expiry hid unverified rollback state');
  assert.equal(storage.size, 0, 'expired commit token remained in session storage');
  assert.equal(notices.filter(args => String(args[0]).includes('expired')).length, 1, 'expiry notice repeated');

  statusPayload = {changes: []};
  await context.refreshHostRollbackStatus(true);
  assert.equal(element('host-rollback-banner').hidden, true);
  assert.equal(element('btn-net-netplan-apply').disabled, false);
  assert.equal(networkReloads, 1, 'effective network state was not reloaded after settlement');

  applyPayload = {token: 'new-token', operation_id: operationID, expires_at: new Date(now - 1000).toISOString()};
  notices.length = 0;
  const yaml = 'network:\n  version: 2\n';
  context.confirmDialog = async (_, options) => {
    assert.equal(options.preview, yaml);
    assert.equal(options.okLabel, 'Apply Netplan configuration');
    return true;
  };
  await context.applyHostWithRollback({kind: 'netplan', applyUrl: '/apply', commitUrl: '/commit', body: {yaml}, msgEl: {}});
  assert.equal(state.token, null, 'expired apply response exposed confirmation');
  assert.ok(notices.some(args => String(args[0]).includes('expired')), 'expired response advertised success');

  const rule = element('zabbix-firewall-status');
  await context.loadZabbixFirewallStatus();
  assert.equal(rule.textContent, 'Managed Zabbix rule: unavailable.');
  firewall = {zabbix_agent_rule: true};
  await context.loadZabbixFirewallStatus();
  assert.equal(rule.textContent, 'Managed Zabbix rule: present.');
  const firewallCapability = {...capability, kind: 'firewall', expires_at: new Date(now + 90000).toISOString()};
  const pendingFirewall = {kind: 'firewall', operation_id: operationID, phase: 'pending',
    expires_at: firewallCapability.expires_at, confirmable: true};
  context.showHostRollbackBanner(pendingFirewall, firewallCapability);
  firewall = {zabbix_agent_rule: false};
  await context.refreshHostRollbackStatus(true);
  assert.equal(rule.textContent, 'Managed Zabbix rule: absent.', 'rule status did not reload after rollback');

  context.showHostRollbackBanner(pendingFirewall, firewallCapability);
  firewall = {zabbix_agent_rule: true};
  await element('btn-host-rollback-keep').onclick();
  assert.equal(rule.textContent, 'Managed Zabbix rule: present.', 'rule status did not reload after confirmation');
  assert.equal(firewallReads, 4);

  const networkStart = page.indexOf('  let networkLoadGeneration =');
  const networkEnd = page.indexOf("  document.getElementById('btn-net-netplan-apply').onclick", networkStart);
  assert.ok(networkStart >= 0 && networkEnd > networkStart, 'network loader not found');
  const editor = {value: '', defaultValue: ''};
  const netplanEditor = {value: '', defaultValue: ''};
  const networkElements = {'net-firewall-rules': editor, 'net-netplan-yaml': netplanEditor,
    'net-firewall-msg': {}, 'net-firewall-load-status': {}, 'net-netplan-msg': {}, 'net-overview': {style: {}}};
  const snapshot = {managed_ruleset: 'managed file', ruleset: 'all kernel tables'};
  const networkContext = {
    document: {getElementById: id => networkElements[id]},
    findEasyWafNetplan: () => 'managed netplan', formatNetOverview: () => 'overview',
    hdr: () => ({}), updateHostRollbackApplyButtons: () => {},
    fetch: async path => ({ok: true, json: async () => path === '/api/v1/host/firewall' ? snapshot : {}})
  };
  vm.runInNewContext(page.slice(networkStart, networkEnd), networkContext);
  await networkContext.loadNetworkTab({skipRollbackStatus: true});
  assert.equal(editor.value, snapshot.managed_ruleset);
  netplanEditor.value = 'netplan draft';
  editor.value = 'firewall draft';
  snapshot.managed_ruleset = 'changed on host';
  await networkContext.loadNetworkTab({skipRollbackStatus: true});
  assert.equal(netplanEditor.value, 'netplan draft');
  assert.equal(editor.value, 'firewall draft');
  assert.equal(editor.defaultValue, 'changed on host');
  assert.match(networkElements['net-firewall-msg'].textContent, /host configuration changed/);
  editor.value = editor.defaultValue;
  delete snapshot.managed_ruleset;
  await networkContext.loadNetworkTab({skipRollbackStatus: true});
  assert.equal(editor.value, '', 'editor exposed unrelated kernel tables');
  const normalFetch = networkContext.fetch;
  editor.value = 'unsaved firewall rules';
  networkContext.fetch = async path => {
    if (path.endsWith('/firewall')) throw new Error('Connection interrupted');
    return normalFetch(path);
  };
  await networkContext.loadNetworkTab({skipRollbackStatus: true});
  assert.equal(networkElements['net-overview'].textContent, 'overview');
  assert.match(networkElements['net-firewall-load-status'].textContent, /Firewall configuration could not be loaded/);
  assert.equal(editor.value, 'unsaved firewall rules');
  networkContext.fetch = async path => path.endsWith('/network')
    ? {ok: true, json: async () => { throw new SyntaxError('Invalid JSON'); }} : normalFetch(path);
  snapshot.managed_ruleset = 'recovered firewall';
  await networkContext.loadNetworkTab({skipRollbackStatus: true});
  assert.match(networkElements['net-overview'].textContent, /Network configuration could not be loaded/);
  assert.equal(editor.defaultValue, 'recovered firewall');
  assert.equal(editor.value, 'unsaved firewall rules');
  assert.equal(networkElements['net-firewall-load-status'].textContent, '');
  networkContext.fetch = normalFetch;
  const delayed = networkContext.loadNetworkTab({skipRollbackStatus: true});
  networkContext.clearNetworkEditors();
  await delayed;
  assert.equal(netplanEditor.value, '', 'a delayed read restored configuration after sign-out');

  const applyStart = page.indexOf('  const btnZabbixFw =');
  const applyEnd = page.indexOf('  const btnNotifySave =', applyStart);
  assert.ok(applyStart >= 0 && applyEnd > applyStart, 'Zabbix controls not found');
  const posted = [];
  const applied = {token: 'test-token', operation_id: operationID, expires_at: pendingFirewall.expires_at};
  let savedCapability;
  const applyContext = {
    cachedSettings: {firewall_zabbix_agent: false},
    document: {getElementById: element}, hdr: () => ({}), toast: () => {},
    confirmDialog: async () => true, loadZabbixFirewallStatus: async () => {},
    saveHostRollbackCapability: cap => {savedCapability = cap;},
    showHostRollbackBanner: () => true, refreshHostRollbackStatus: async () => {},
    fetch: async (path, init) => {
      if (path === '/api/v1/settings') return {ok: true, json: async () => ({firewall_zabbix_agent: false})};
      assert.equal(path, '/api/v1/host/firewall/zabbix-agent');
      assert.equal(init.method, 'POST');
      posted.push(JSON.parse(init.body));
      return {ok: true, json: async () => applied};
    }
  };
  element('firewall-zabbix-agent').checked = false;
  vm.runInNewContext(page.slice(applyStart, applyEnd), applyContext);
  await element('btn-zabbix-firewall-apply').onclick();
  assert.deepEqual(posted, [{enabled: false, reapply: true, rollback_seconds: 90}]);
  assert.equal(savedCapability.commit_url, '/api/v1/host/firewall/commit');
  assert.equal(savedCapability.token, applied.token);
})().catch(err => {console.error(err); process.exitCode = 1});
`
