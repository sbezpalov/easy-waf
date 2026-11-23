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
const zabbixStart = page.indexOf('  let zabbixFirewallRead = 0;');
const zabbixEnd = page.indexOf('  function loadSettingsTab()', zabbixStart);
assert.ok(zabbixStart >= 0 && zabbixEnd > zabbixStart, 'Zabbix status loader not found');
let now = Date.now(), nextTimer = 0;
const timers = new Map(), notices = [], elements = new Map(), storage = new Map();
const state = {timer: null, polling: false, statusUnknown: true, statusWarned: false, expiryNotified: false};
const element = id => {
  if (!elements.has(id)) elements.set(id, {hidden: true, classList: {
    add: () => {element(id).hidden = true}, remove: () => {element(id).hidden = false},
    toggle: (_, force) => {element(id).hidden = !!force},
    contains: cls => id === 'tab-settings' && cls === 'active'
  }});
  return elements.get(id);
};
let applyPayload, statusPayload = {changes: []}, networkReloads = 0;
let firewall = {}, firewallReads = 0;
const context = {assert, hostRollback: state, Date: class extends Date {static now() {return now}},
  currentRole: 'admin',
  HOST_ROLLBACK_STORAGE_KEY: 'test-host-rollback',
  document: {getElementById: element}, setInterval: fn => {timers.set(++nextTimer, fn); return nextTimer},
  clearInterval: id => timers.delete(id), toast: (...args) => notices.push(args),
  confirmDialog: async () => true, hdr: () => ({}), apiMessage: async () => 'failed',
  sessionStorage: {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
  loadNetworkTab: async () => {networkReloads++},
  fetch: async (url, options) => {
    if (url === '/api/v1/host/firewall') {
      firewallReads++;
      assert.equal(options.cache, 'no-store');
      return {ok: true, json: async () => firewall};
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
  await context.refreshHostRollbackStatus();
  assert.equal(state.statusUnknown, false);
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
  await context.applyHostWithRollback({kind: 'netplan', applyUrl: '/apply', commitUrl: '/commit', body: {}, msgEl: {}});
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
})().catch(err => {console.error(err); process.exitCode = 1});
`
