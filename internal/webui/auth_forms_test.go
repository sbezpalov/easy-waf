// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import "testing"

func TestPrivilegedConfirmationLifecycle(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0,'utf8');
function deferred() {
  let resolve;
  const promise = new Promise(done => {resolve = done;});
  return {promise, resolve};
}
async function scenario(mode) {
  const entered = deferred(), delayed = deferred();
  let token = 'original', prompts = 0, attempts = 0, writes = 0;
  const window = {location:{origin:'https://panel.example'},fetch:async (path, init) => {
    if (path === '/api/v1/auth/confirm') {
      attempts++;
      if (mode === 'delayed') {entered.resolve(); await delayed.promise;}
      if (mode === 'service') return Response.json({}, {status:500});
      if (mode === 'limited') return Response.json({}, {status:429});
      if (mode === 'incorrect' && attempts === 1) return Response.json({error:'password incorrect'}, {status:401});
      return Response.json({token:'confirmed'});
    }
    writes++;
    if (mode === 'expired') {
      entered.resolve();
      await delayed.promise;
      return Response.json({}, {status:401});
    }
    if (writes === 1) return Response.json({error:'step_up_required'}, {status:403});
    assert.equal(init.headers.get('Authorization'), 'Bearer confirmed');
    return Response.json({});
  }};
  const ctx = vm.createContext({window, URL, Request, Response, Headers, AbortController,
    sessionStorage:{getItem:()=>token,setItem:(_,value)=>{token=value;},removeItem:()=>{token='';}},
    clearNetworkEditors(){},clearTOTPSecrets(){},clearManagementTLSForm(){},mcpConnectionsGeneration:0,
    passwordDialog:async (message,signal) => {
      prompts++;
      assert.ok(prompts <= 2);
      if (mode === 'dialog') {
        entered.resolve();
        return new Promise(done => signal.addEventListener('abort',()=>done(null)));
      }
      if (prompts === 2) assert.match(message,/Incorrect password/);
      return 'fixture';
    }});
  function include(start,end) {
    const a=page.indexOf(start), b=page.indexOf(end,a);
    assert.ok(a>=0 && b>a);
    vm.runInContext(page.slice(a,b),ctx);
  }
  include('  const TOK =','  let modalSequence');
  include('  const nativeFetch','  const HASH_TO_PANEL');
  const result=window.fetch('/api/v1/example',{method:'POST'});
  if (mode === 'delayed' || mode === 'dialog' || mode === 'expired') {
    await entered.promise;
    vm.runInContext("setTok(''); setTok('other')",ctx);
    delayed.resolve();
    assert.equal((await result).status,409);
    assert.equal(token,'other');
    assert.equal(attempts,mode==='delayed'?1:0);
    assert.equal(writes,1);
  } else if (mode === 'service' || mode === 'limited') {
    const response=await result;
    assert.equal(response.status,mode==='limited'?429:503);
    assert.match((await response.json()).error,/try again later|retry the operation/i);
    assert.equal(prompts,1);
    assert.equal(writes,1);
  } else {
    assert.equal((await result).status,200);
    assert.equal(prompts,mode==='incorrect'?2:1);
    assert.equal(writes,2);
  }
}
Promise.all(['success','incorrect','delayed','dialog','expired','service','limited'].map(scenario))
  .catch(err=>{console.error(err);process.exitCode=1});
`)
}

func TestAuthFormsAndMCPContinuation(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0,'utf8');
const elements = new Map();
const el = id => {
  if (!elements.has(id)) elements.set(id, {value:'',focus(){this.focused=true;},
    classList:{add(){},remove(){}},reset(){this.wasReset=true;}});
  return elements.get(id);
};
for (const name of ['login','enroll','pass']) {
  const start = page.indexOf('<form id="' + name + '-form"');
  assert.ok(start >= 0);
  const form = page.slice(start,page.indexOf('</form>',start));
  assert.ok(form.includes('type="submit" id="btn-' + name + '"'));
  assert.ok(form.includes('id="' + name + '-err" role="alert"'));
}
const hash='#mcp?state=fixture';
const location={hash};
let response, calls=0;
const ctx=vm.createContext({document:{getElementById:el},location,
  withBusy:async (button,fn)=>{button.disabled=true;try{await fn();}finally{button.disabled=false;}},
  fetch:async()=>{calls++;return response;},hdr:()=>({}),show(){},setTok(){},refreshSession:async()=>{}});
const start=page.indexOf('  function bindAuthForm(');
vm.runInContext(page.slice(start,page.indexOf("  document.getElementById('btn-logout').onclick",start)),ctx);
async function submit(name){
  let prevented=false;
  await el(name+'-form').onsubmit({preventDefault(){prevented=true;}});
  assert.equal(prevented,true);
}
async function run(){
  response={ok:false,json:async()=>({error:'totp_required'})};
  await submit('login');
  assert.equal(el('login-totp').focused,true);
  response={ok:true,json:async()=>({token:'fixture',must_change_password:true})};
  await Promise.all([submit('login'),submit('login')]);
  assert.equal(calls,2);
  el('new-pass').value='fixture-password';
  await submit('pass');
  assert.equal(el('new-pass2').focused,true);
  assert.equal(calls,2);
  el('new-pass2').value='fixture-password';
  await submit('pass');
  assert.equal(calls,3);
  assert.equal(location.hash,hash);
  await submit('enroll');
  assert.equal(el('enroll-form').wasReset,true);
}
run().catch(e=>{console.error(e);process.exitCode=1});
`)
}

// Verify that one-time recovery codes stay available to save within the session
// and that delayed responses cannot restore secrets after logout.
func TestTOTPSecretLifecycle(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {value:'',textContent:'',focus(){},removeAttribute(name){delete this[name];},
    classList:{add(){},remove(){},toggle(){}}});
  return elements.get(id);
}
const ctx = vm.createContext({document:{getElementById:element},hdr:()=>({}),
  sessionStorage:{removeItem(){}},mcpConnectionsGeneration:0,clearNetworkEditors(){},clearManagementTLSForm(){}});
function include(start,end) {
  const a=page.indexOf(start), b=page.indexOf(end,a);
  assert.ok(a>=0 && b>a);
  vm.runInContext(page.slice(a,b),ctx);
}
include('  const TOK =','  const hdr =');
include('  let totpGeneration','  function fillAppMaintenance');
include("  document.getElementById('btn-totp-setup').onclick","  document.getElementById('btn-pu-create').onclick");
const response={ok:true,json:async()=>({secret:'fixture',otpauth_uri:'otpauth://fixture',recovery_codes:['test-recovery']})};
async function run() {
  ctx.fetch=async()=>response;
  await element('btn-totp-setup').onclick();
  assert.equal(element('totp-secret').textContent,'fixture');
  element('totp-code').value='123456';
  await element('btn-totp-enable').onclick();
  assert.equal(element('totp-uri').href,undefined);
  assert.equal(element('totp-code').value,'');
  assert.equal(element('totp-secret').textContent,'');
  assert.match(element('totp-recovery').textContent,/test-recovery/);
  element('btn-totp-dismiss').onclick();
  assert.equal(element('totp-recovery').textContent,'');
  for(const action of ['setup','enable']) {
    let finish;
    ctx.fetch=()=>new Promise(resolve=>{finish=resolve;});
    const pending=element('btn-totp-'+action).onclick();
    element('totp-recovery').textContent='test-recovery';
    vm.runInContext("setTok('')",ctx);
    finish(response);
    await pending;
    assert.equal(element('totp-recovery').textContent,'');
    assert.equal(element('totp-secret').textContent,'');
    assert.equal(element('totp-uri').href,undefined);
  }
}
run().catch(err=>{console.error(err);process.exitCode=1;});
`)
}
