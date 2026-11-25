// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import "testing"

func TestMCPPanelStatusAndRetry(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
assert.match(page, /href="#mcp" class="nav-link" data-tab="mcp"/);
assert.match(page, /case 'mcp':\s+void loadMCPStatus\(\)/);
const status = {}, refresh = {};
let response;
const context = vm.createContext({
  document: {getElementById: id => ({'mcp-refresh': refresh, 'mcp-service-status': status})[id]},
  hdr: () => ({}),
  fetch: async path => {
    assert.equal(path, '/api/v1/integrations/mcp/status');
    return response;
  }
});
const start = page.indexOf('  async function loadMCPStatus()');
const end = page.indexOf('  async function loadSystemTab()', start);
assert.ok(start >= 0 && end > start);
vm.runInContext(page.slice(start, end), context);
async function run() {
  for (const [state, label] of [['inactive', 'Stopped'], ['failed', 'Failed'],
      ['unknown', 'Service state unavailable'], ['active', 'Running']]) {
    response = {ok: true, json: async () => ({active_state: state})};
    const pending = refresh.onclick();
    assert.equal(refresh.disabled, true);
    assert.equal(status.textContent, 'Checking service…');
    await pending;
    assert.equal(refresh.disabled, false);
    assert.equal(status.textContent, label);
  }
  response = {ok: false};
  await refresh.onclick();
  assert.match(status.textContent, /Try refreshing/);
  assert.equal(refresh.disabled, false);
}
run().catch(error => {console.error(error); process.exitCode = 1});
`)
}
