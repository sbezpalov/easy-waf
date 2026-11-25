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

func TestMCPConsentAndGrantControls(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const elements = new Map();
function element() {
  return {dataset: {}, children: [], append(...values) {this.children.push(...values);},
    replaceChildren() {this.children = [];}};
}
const document = {createElement: element, getElementById(id) {
  if (!elements.has(id)) elements.set(id, element());
  return elements.get(id);
}};
const origin = 'https://waf.example';
const location = {origin, protocol:'https:', hash:'#mcp?client_name=OpenClaw&redirect_uri=https%3A%2F%2Fgateway.example%2Fcallback',
  replace(url) {this.destination = url;}};
let grants = [{id:'fixture',name:'OpenClaw',approved_by:'admin'}], approved = false;
const ctx = vm.createContext({document, location, currentRole:'admin', URLSearchParams,
  hdr:()=>({}), withBusy:(_,fn)=>fn(), fetch: async (path,opts) => {
    if (opts.method === 'POST') {
      assert.equal(path,'/api/v1/integrations/mcp/approve');
      assert.equal(JSON.parse(opts.body).query, location.hash.split('?')[1]);
      approved = true;
      return {ok:true,json:async()=>({redirect:'https://gateway.example/callback?code=fixture'})};
    }
    if (opts.method === 'DELETE') {
      assert.equal(path,'/api/v1/integrations/mcp/grants/fixture');
      grants = [];
      return {ok:true};
    }
    return {ok:true,json:async()=>grants};
  }});
const start = page.indexOf('  let mcpConnectionsGeneration'), end = page.indexOf('  async function loadMCPStatus()',start);
vm.runInContext(page.slice(start,end),ctx);
async function run(){
  await ctx.loadMCPConnections();
  assert.equal(elements.get('mcp-copy').dataset.copy,origin+'/mcp');
  assert.equal(elements.get('mcp-consent').hidden,false);
  assert.match(elements.get('mcp-consent-detail').textContent,/gateway\.example/);
  assert.equal(approved,false);
  await elements.get('mcp-approve').onclick({currentTarget:{}});
  assert.equal(approved,true);
  assert.match(location.destination,/callback/);
  location.hash='#mcp';
  await elements.get('mcp-grants').children[0].children[1].onclick();
  assert.equal(elements.get('mcp-grants').textContent,'No approved connections.');
}
run().catch(e=>{console.error(e);process.exitCode=1;});
`)
}
