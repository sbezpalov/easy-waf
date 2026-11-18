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
	for _, scenario := range []string{"save_success", "save_new_success", "save_clear_health_success", "save_update_health_success", "save_manual", "save_legacy", "save_rejected", "save_missing_cert", "mode_success", "mode_manual", "mode_legacy", "mode_rejected", "mode_cancelled", "maintenance_success", "maintenance_manual", "maintenance_rejected", "maintenance_cancelled"} {
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
    elements.set(id, {value: '', checked: false, disabled: false, textContent: '', dataset: {}, innerHTML: '',
      classList: {toggle: (name, on) => on ? classes.add(name) : classes.delete(name), contains: name => classes.has(name)}});
  }
  return elements.get(id);
}
Object.entries({'app-edit-id': 'fixture-app', 'listen-mode': 'http_only', name: 'Fixture',
  host: 'fixture.invalid', backend: '127.0.0.1', port: '8123', profile: 'balanced'})
  .forEach(([id, value]) => {element(id).value = value});
if (scenario === 'save_missing_cert') element('listen-mode').value = 'https_only';
if (scenario === 'save_new_success') element('app-edit-id').value = '';
const healthPath = element('app-health-path');
healthPath.defaultValue = scenario === 'save_new_success' ? '' : '/ready';
const sentHealthPath = {save_new_success: '', save_clear_health_success: '', save_update_health_success: '/next'}[scenario];
healthPath.value = ' ' + (sentHealthPath ?? healthPath.defaultValue) + ' ';
const policyDraft = [
  {id: 'watch', action: 'count', path: '/api', methods: 'get, HEAD', sources: '192.0.2.0/24', header: 'User-Agent', prefix: 'App '},
  {id: 'deny', action: 'block', path: '/api', methods: 'POST'}
];
element('publication-rules').children = policyDraft.map(rule => ({
  querySelector: selector => ({value: rule[selector.slice(5)] || ''})
}));
const requests = [], notices = [];
let cleared = 0, collapsed = 0, refreshed = 0;
const context = {pendingApply: true, document: {getElementById: element},
  appsListCache: [{id: 'fixture-app', enabled: false, security: {mode: 'balanced'}}],
  hdr: () => ({}), encodeURIComponent, esc: value => String(value),
  fetch: async (path, init) => {
    requests.push([path, init]);
    if (path === '/api/v1/edge/status') {
      const pending = !scenario.endsWith('_success');
      return {ok: true, json: async () => ({saved_generation: 9, applied_generation: pending ? 8 : 9,
        pending, last_apply: null, runtime: {state: 'known'}})};
    }
    return {ok: !scenario.endsWith('_rejected'), headers: {get: name => {assert.equal(name, 'X-Easy-Waf-Applied'); return scenario.endsWith('_legacy') ? null : scenario.endsWith('_manual') ? 'false' : 'true'}}};
  },
  withBusy: async (button, operation) => operation(),
  toast: (...args) => notices.push(args), apiMessage: async () => 'Apply rejected',
  confirmDialog: async () => !scenario.endsWith('_cancelled'), loadApps: async () => {refreshed++},
  parseBackendServers: () => [], collectRestrictedPaths: () => [], collectPathPolicy: () => null,
  readPublicationBasics: () => ({name: element('name').value, public_host: element('host').value,
    backend_host: element('backend').value, backend_port: Number(element('port').value),
    listen_mode: element('listen-mode').value, certificate_id: element('app-cert').value}),
  selectedPublicationCertificate: () => null,
  validatePublicationBasics: draft => draft.listen_mode !== 'http_only' && !draft.certificate_id
    ? {certificate: 'Choose a ready certificate for HTTPS.'} : {},
  showPublicationErrors: () => {}, clearPublicationErrors: () => {},
  securityForPublication: (mode, previous) => previous || {mode: mode || 'balanced'},
  withBodyPolicy: value => value,
  clearAppFormFields: () => {cleared++}, setAppFormCollapsed: on => {if (on) collapsed++}};
vm.createContext(context);
vm.runInContext("const publicationRulesBox = document.getElementById('publication-rules');", context);
function include(from, until) {
  const start = page.indexOf(from), end = page.indexOf(until, start);
  assert.ok(start >= 0 && end > start, 'embedded handler missing: ' + from);
  vm.runInContext(page.slice(start, end), context);
}
include('  function markPendingApply(', '  function copyBtn(');
include('  function collectPublicationRules(', '  function fillPathPolicy(');
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
  const mutations = requests.filter(([path]) => path !== '/api/v1/edge/status');
  assert.equal(mutations.length, 1, 'one mutation; no extra explicit Apply request');
  assert.equal(mutations[0][1].method, 'POST');
  assert.equal(mutations[0][0], scenario.startsWith('save_') ? '/api/v1/applications' : scenario.startsWith('mode_') ? '/api/v1/applications/fixture-app/security/mode' : '/api/v1/applications/fixture-app/maintenance');
  if (scenario.startsWith('save_')) {
    const body = JSON.parse(mutations[0][1].body);
    assert.equal(body.id, scenario === 'save_new_success' ? undefined : 'fixture-app');
    assert.equal(body.enabled, scenario === 'save_new_success' ? true : undefined, 'editing a publication must preserve its stored state');
    assert.equal(body.health_path, sentHealthPath);
    assert.deepEqual(body.policy_rules, [
      {id:'watch', action:'count', match:{path_prefix:'/api', methods:['GET', 'HEAD'], source_cidrs:['192.0.2.0/24'], header:'User-Agent', header_prefix:'App '}},
      {id:'deny', action:'block', match:{path_prefix:'/api', methods:['POST'], source_cidrs:[], header:'', header_prefix:''}}
    ]);
  }
  if (scenario.endsWith('_rejected')) {
    assert.equal(context.pendingApply, true, 'rejected mutation must preserve pending state');
    assert.equal(cleared + collapsed + refreshed, 0, 'keep rejected form for correction');
    assert.ok(notices.some(([, kind]) => kind === 'err'));
    if (scenario === 'mode_rejected') assert.equal(select.value, 'balanced');
  } else {
    assert.equal(requests.filter(([path]) => path === '/api/v1/edge/status').length, 1, 'successful mutation must refresh persistent edge truth');
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
