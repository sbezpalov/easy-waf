// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import "testing"

func TestSystemDNSIdentityControls(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const a = page.indexOf('  const identityField ='), b = page.indexOf('  refreshSession();', a);
assert.ok(a >= 0 && b > a);
const elements = new Map();
function field(id) {
  if (!elements.has(id)) elements.set(id, {value:'',defaultValue:''});
  return elements.get(id);
}
let saved = null, allow = true;
const calls = [];
const context = {document:{getElementById:field},URL,location:{origin:'https://192.0.2.1:8443'},
  managementTLSGeneration:0, formatHostTime:t=>t, hdr:extra=>extra||{},
  withBusy:(_,fn)=>fn(),confirmDialog:async()=>allow,
  fetch:async(path,options)=>{
    const body = options.body && JSON.parse(options.body);
    calls.push({path,body,method:options.method,headers:options.headers});
    if (path.endsWith('/hostname')) return {ok:true,json:async()=>({hostname:body?.hostname || 'waf'})};
    if (options.method==='PUT') saved={hostname:body.hostname,sha256:'fingerprint',certificate_pem:'public',expires_at:'2027'};
    if (options.method==='DELETE') saved=null;
    return {ok:true,json:async()=>saved};
  }};
vm.runInNewContext(page.slice(a,b),context);
async function run() {
  await context.loadSystemIdentity();
  assert.equal(field('host-name').value,'waf');
  assert.equal(field('mgmt-identity-details').hidden,true);
  field('mgmt-name').value='waf.home.arpa';
  await context.changeIdentity('save');
  assert.equal(field('mgmt-identity-mcp').textContent,'https://waf.home.arpa:8443/mcp');
  assert.equal(field('mgmt-identity-details').hidden,false);
  allow=false;
  const count=calls.length;
  await context.changeIdentity('remove');
  assert.equal(calls.length,count);
  allow=true;
  await context.changeIdentity('renew');
  assert.equal(calls.at(-1).headers['X-Identity-SHA256'],'fingerprint');
  assert.equal(calls.at(-1).body.renew,true);
  await context.changeIdentity('remove');
  assert.equal(field('mgmt-identity-details').hidden,true);
  field('host-name').value='new-host';
  await field('host-name-form').onsubmit({preventDefault(){}});
  assert.equal(calls.at(-1).path,'/api/v1/host/hostname');
  assert.equal(calls.at(-1).body.hostname,'new-host');
}
run().catch(err=>{console.error(err);process.exitCode=1;});
`)
}

func TestManagementTLSFormSessionBoundary(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const cert = {value:'test certificate'}, key = {value:'test key'}, msg = {}, button = {};
const elements = {'tls-cert':cert, 'tls-key':key, 'tls-msg':msg, 'btn-tls-save':button};
const ctx = vm.createContext({document:{getElementById:id=>elements[id]}, hdr:()=>({}),
  clearNetworkEditors(){},clearSettingsDrafts(){}, clearSystemIdentity(){}, clearTOTPSecrets(){}, mcpConnectionsGeneration:0, sessionStorage:{removeItem(){}},
  apiMessage: async r=>r.message, fetch:async()=>({ok:false,message:'Invalid key pair'})});
function include(start,end) {
  const a=page.indexOf(start), b=page.indexOf(end,a);
  assert.ok(a>=0 && b>a);
  vm.runInContext(page.slice(a,b),ctx);
}
include("  const TOK =", "  const hdr =");
include("  let managementTLSGeneration", "  document.getElementById('btn-ipbl-fetch-cidrs-save')");
const submit = () => button.onclick({currentTarget:button});
async function run() {
  await submit();
  assert.equal(msg.textContent,'Invalid key pair');
  assert.equal(key.value,'test key');
  let finish, calls=0;
  ctx.fetch = () => {calls++;return new Promise(resolve=>{finish=resolve;});};
  const previous = submit();
  await submit();
  assert.equal(calls,1);
  vm.runInContext("setTok('')",ctx);
  assert.equal(key.value,'');
  assert.equal(cert.value,'');
  assert.equal(button.disabled,false);
  cert.value='next certificate'; key.value='next key';
  finish({ok:true});
  await previous;
  assert.equal(msg.textContent,'');
  assert.equal(key.value,'next key');
  ctx.fetch=async()=>{throw Error('disconnected');};
  await submit();
  assert.match(msg.textContent,/Could not confirm installation/);
  ctx.fetch=async()=>({ok:true});
  await submit();
  assert.equal(key.value,'');
  assert.equal(cert.value,'');
  assert.match(msg.textContent,/installed/);
}
run().catch(err=>{console.error(err);process.exitCode=1;});
`)
}

func TestCertificateInventoryRefresh(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {appendChild(row) {this.innerHTML += row.innerHTML;}});
  return elements.get(id);
}
const ctx = vm.createContext({document:{getElementById:element,createElement:()=>({})}, hdr:()=>({})});
const start = page.indexOf('  let certInventoryGeneration'), end = page.indexOf('  function decisionsCount',start);
assert.ok(start >= 0 && end > start);
vm.runInContext(page.slice(start,end),ctx);
const empty = {total:0, valid:0, expired:0, expiring_soon:0, certificates:[]};
const success = data => ({ok:true,json:async()=>data});
async function run() {
  let release;
  ctx.fetch = () => new Promise(resolve => {release = resolve;});
  const old = ctx.loadCertDashboard();
  for (const fetch of [
    async()=>{throw Error('offline');},
    async()=>({ok:true,json:async()=>{throw SyntaxError('JSON');}}),
    async()=>success({...empty, total:1}),
    async()=>success({...empty, certificates:null}),
    async()=>success({...empty, total:1, certificates:[null]})
  ]) {
    ctx.fetch = fetch;
    element('cert-sum-total').textContent = '12';
    await ctx.loadCertDashboard();
    assert.match(element('cert-dash-msg').textContent,/inventory unavailable/);
    assert.equal(element('cert-table-body').innerHTML,'');
    assert.equal(element('cert-sum-total').textContent,'—');
  }
  release(success(empty));
  await old;
  assert.match(element('cert-dash-msg').textContent,/inventory unavailable/);
  ctx.fetch = async()=>success(empty);
  await ctx.loadCertDashboard();
  assert.equal(element('cert-dash-msg').textContent,'');
  assert.equal(element('cert-sum-total').textContent,'0');
  assert.match(element('cert-table-body').innerHTML,/No certificates yet/);
  const certificate = {id:'cert/123', primary_domain:'app.example'};
  const calls = [], notices = [];
  let confirm = false, outcome;
  ctx.withBusy = async (btn, fn) => {
    btn.disabled = true;
    try {return await fn();} finally {btn.disabled = false;}
  };
  ctx.confirmDialog = async message => {assert.match(message,/app\.example/); return confirm;};
  ctx.toast = (message,kind) => notices.push([message,kind]);
  ctx.apiMessage = async () => 'Certificate is in use.';
  ctx.fetch = async (path, opts) => {
    calls.push([opts.method || 'GET',path]);
    if (!opts.method) return success(empty);
    if (!outcome) throw Error('reply lost');
    return outcome;
  };
  const button = {dataset:{certAction:'delete'}};
  await ctx.runCertificateAction(button,certificate);
  assert.deepEqual(calls,[]);
  confirm = true;
  for (const action of ['delete','issue','renew']) {
    button.dataset.certAction = action;
    calls.length = 0;
    outcome = action === 'issue' ? {ok:false,status:503} : undefined;
    await ctx.runCertificateAction(button,certificate);
    assert.deepEqual(calls,[
      action === 'delete' ? ['DELETE','/api/v1/certificates/cert%2F123'] :
        ['POST','/api/v1/certificates/cert%2F123/request-issue'],
      ['GET','/api/v1/certificates/summary']
    ]);
    assert.equal(notices.at(-1)[1],'warn');
  }
  outcome = {ok:false,status:409};
  button.dataset.certAction = 'delete';
  calls.length = 0;
  await ctx.runCertificateAction(button,certificate);
  assert.equal(calls.length,1);
  assert.equal(element('cert-dash-msg').textContent,'Certificate is in use.');
  outcome = {ok:true,status:204};
  await ctx.runCertificateAction(button,certificate);
  assert.deepEqual(notices.at(-1),['Certificate deleted for app.example.','ok']);
}
run().catch(err=>{console.error(err);process.exitCode=1;});
`)
}
