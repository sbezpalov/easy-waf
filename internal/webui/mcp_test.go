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
    cloneNode:element, removeAttribute(){}, setAttribute(){}, replaceChildren() {this.children = [];}};
}
const document = {createElement: element, getElementById(id) {
  if (!elements.has(id)) elements.set(id, element());
  return elements.get(id);
}};
const origin = 'https://waf.example';
const location = {origin, protocol:'https:', hash:'#mcp?client_name=OpenClaw&redirect_uri=https%3A%2F%2Fgateway.example%2Fcallback',
  replace(url) {this.destination = url;}};
let dropApproval = false, dropRevocation = false, offline = false, listUnavailable = false, deletions = 0;
const notices = [];
let grants = [{id:'fixture',name:'OpenClaw',approved_by:'admin',status:'connected',
  issuer:'https://waf-alias.example',redirect_uri:'https://gateway.example/callback'}], approved = false;
let identity = null;
const ctx = vm.createContext({document, location, currentRole:'admin', URL, URLSearchParams,
  hdr:()=>({}), withBusy:(_,fn)=>fn(), toast:(message,kind)=>notices.push([kind,message]), fetch: async (path,opts) => {
    if (opts.method === 'POST') {
      if (path === '/api/v1/integrations/mcp/deny') {
        assert.equal(JSON.parse(opts.body).query, location.hash.split('?')[1]);
        return {ok:true,json:async()=>({redirect:'https://gateway.example/callback?error=access_denied'})};
      }
      if (dropApproval) throw new Error('connection lost');
      assert.equal(path,'/api/v1/integrations/mcp/approve');
      assert.equal(JSON.parse(opts.body).query, location.hash.split('?')[1]);
      assert.equal(JSON.parse(opts.body).lifetime,'until_revoked');
      approved = true;
      return {ok:true,json:async()=>({redirect:'https://gateway.example/callback?code=fixture'})};
    }
    if (opts.method === 'PATCH') {
      assert.equal(JSON.parse(opts.body).lifetime,'7d');
      grants[0].valid_until='2030-01-01';
      return {ok:true};
    }
    if (opts.method === 'DELETE') {
      deletions++;
      assert.equal(path,'/api/v1/integrations/mcp/grants/fixture');
      grants = [];
      if (dropRevocation) throw new Error('reply lost');
      return {ok:true};
    }
    if (offline) throw new Error('offline');
    if (path === '/api/v1/settings/management-identity') return {ok:true,json:async()=>identity};
    if (listUnavailable) return {ok:false};
    return {ok:true,json:async()=>grants};
  }});
const start = page.indexOf('  let mcpConnectionsGeneration'), end = page.indexOf('  async function loadMCPStatus()',start);
vm.runInContext(page.slice(start,end),ctx);
async function run(){
  await ctx.loadMCPConnections();
  assert.equal(elements.get('mcp-copy').dataset.copy,origin+'/mcp');
  identity = {hostname:'waf.home.arpa'};
  await ctx.loadMCPConnections();
  assert.equal(elements.get('mcp-copy').dataset.copy,'https://waf.home.arpa/mcp');
  assert.equal(elements.get('mcp-consent').hidden,false);
  assert.match(elements.get('mcp-consent-detail').textContent,/gateway\.example/);
  listUnavailable = true;
  await ctx.loadMCPConnections();
  assert.match(elements.get('mcp-grants').textContent,/Could not load approved connections/);
  assert.equal(elements.get('mcp-copy').hidden,false);
  assert.equal(elements.get('mcp-copy').dataset.copy,'https://waf.home.arpa/mcp');
  assert.equal(elements.get('mcp-consent').hidden,false);
  assert.equal(elements.get('mcp-approve').disabled,false);
  assert.equal(approved,false);
  await elements.get('mcp-deny').onclick();
  assert.match(location.destination,/error=access_denied/);
  assert.equal(approved,false);
  listUnavailable = false;
  await ctx.loadMCPConnections();
  delete location.destination;
  dropApproval = true;
  await elements.get('mcp-approve').onclick({currentTarget:{}});
  assert.equal(notices.at(-1)[0],'warn');
  assert.equal(location.destination, undefined);
  dropApproval = false;
  elements.get('mcp-approval-lifetime').value = 'until_revoked';
  await elements.get('mcp-approve').onclick({currentTarget:{}});
  assert.equal(approved,true);
  assert.match(location.destination,/callback/);
  const realFetch = ctx.fetch;
  const consentHash = location.hash;
  for (const destination of ['#dashboard', consentHash + '&state=another']) {
    delete location.destination;
    let finish;
    ctx.fetch = (path, opts) => opts.method === 'POST' ?
      new Promise(resolve => {finish = resolve;}) : realFetch(path, opts);
    const pending = elements.get('mcp-approve').onclick();
    assert.equal(elements.get('mcp-deny').disabled,true);
    assert.equal(elements.get('mcp-refresh-grants').disabled,true);
    location.hash = destination;
    if (destination.startsWith('#mcp?')) await ctx.loadMCPConnections();
    finish({ok:true,json:async()=>({redirect:'https://gateway.example/old-callback'})});
    await pending;
    assert.equal(location.destination,undefined,'late consent response redirected another view');
    location.hash = consentHash;
    await ctx.loadMCPConnections();
    assert.equal(elements.get('mcp-approve').disabled,false);
  }
  ctx.fetch = realFetch;
  location.hash='#mcp';
  await ctx.loadMCPConnections();
  const grantText = elements.get('mcp-grants').children[0].children[0];
  assert.ok(grantText.includes(grants[0].issuer) && grantText.includes(grants[0].redirect_uri));
  const line = elements.get('mcp-grants').children[0];
  assert.match(grantText,/Until revoked/);
  line.children[3].value='7d';
  ctx.formatHostTime = x=>x;
  await line.children[5].onclick();
  assert.match(elements.get('mcp-grants').children[0].children[0],/Expires 2030-01-01/);
  const original = grants;
  await elements.get('mcp-grants').children[0].children[1].onclick();
  assert.equal(notices.at(-1)[0], 'ok');
  assert.equal(elements.get('mcp-grants').textContent,'No approved connections.');
  grants = original;
  await elements.get('mcp-refresh-grants').onclick();
  dropRevocation = offline = true;
  await elements.get('mcp-grants').children[0].children[1].onclick();
  assert.equal(notices.at(-1)[0], 'warn');
  assert.match(elements.get('mcp-grants').textContent,/Could not load/);
  assert.equal(elements.get('mcp-refresh-grants').disabled,false);
  offline = false;
  await elements.get('mcp-refresh-grants').onclick();
  assert.equal(elements.get('mcp-grants').textContent,'No approved connections.');
  assert.equal(deletions,2,'refresh must never repeat a revocation');
}
run().catch(e=>{console.error(e);process.exitCode=1;});
`)
}
