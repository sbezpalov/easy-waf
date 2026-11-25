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

func TestACMEConfigurationFeedback(t *testing.T) {
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
	cmd := exec.CommandContext(ctx, node, "-e", acmeReadinessTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ACME configuration feedback: %v\n%s", err, output)
	}
}

const acmeReadinessTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
function include(context, from, until) {
 const start = page.indexOf(from), end = page.indexOf(until, start);
 assert.ok(start >= 0 && end > start, 'missing production code: ' + from);
 vm.runInContext(page.slice(start, end), context);
}
function fixture() {
 const elements = {};
 const get = id => elements[id] ||= {textContent:'',className:'',value:'',checked:false,checkValidity:()=>true,
   getAttribute(key){return this[key];},setAttribute(key,value){this[key]=value;},removeAttribute(key){delete this[key];}};
 const context = {document:{getElementById:get,addEventListener(name,fn){this[name]=fn;}},sessionGeneration:1,cachedSettings:null,hdr:()=>({}),
  loadIpwlToggleFromSettings(){},loadBotProtectionFromSettings(){},loadEdgeNetworkFromSettings(){},
  loadGeoIPFromSettings(){},loadIpblFetchCIDRsFromSettings(){}};
 vm.createContext(context);
 include(context, '  function renderACMEConfigurationStatus(', '  async function loadSettingsPanel(');
 include(context, '  async function loadSettingsPanel(', '  function loadIpwlToggleFromSettings(');
 include(context, "  document.getElementById('btn-acme-settings-save').onclick", "  document.getElementById('btn-cs-settings-save').onclick");
 const busyStart=page.indexOf('  async function withFocusableBusy(');
 vm.runInContext(page.slice(busyStart,page.indexOf('\n  }',busyStart)+4),context);
 include(context, '  async function saveCredentialSettings(', "  const btnNotifyTest =");
 include(context, "  document.getElementById('btn-cs-settings-save').onclick", "  document.getElementById('btn-waf-security-save').onclick");
 return {context,get};
}
async function run() {
 for (const [button,field,message] of [
   ['btn-cs-settings-save','cs-lapi-key','cs-settings-msg'],
   ['btn-notify-save','notify-telegram-token','settings-msg']]) {
  for (const mode of ['unchanged','edited','session-ended','offline']) {
   const {context:c,get}=fixture();
   c.cachedSettings={acme_staging:true};
   get(field).value='first-fixture';
   let finish, calls=0;
   c.fetch=(_url,options)=>{
    calls++;
    assert.equal(options.method,'PATCH');
    assert.ok(Object.values(JSON.parse(options.body)).includes('first-fixture'));
    return new Promise((resolve,reject)=>{finish=mode==='offline'?()=>reject(Error('offline')):
     ()=>resolve({ok:true,json:async()=>({acme_staging:false})});});
   };
   const saving=get(button).onclick();
   if(mode!=='unchanged')get(field).value='later-fixture';
   await get(button).onclick();
   assert.equal(calls,1);
   if(mode==='session-ended'){c.sessionGeneration++;c.cachedSettings=null;}
   finish();await saving;
   assert.equal(get(field).value,mode==='unchanged'?'':'later-fixture');
   const feedback=get(message).textContent;
   assert.doesNotMatch(feedback,/fixture/);
   if(mode==='session-ended'){assert.equal(c.cachedSettings,null);assert.equal(feedback,'');}
   if(mode==='offline')assert.match(feedback,/unknown/);
   if(mode==='edited')assert.match(feedback,/draft/);
   assert.equal(get(button).getAttribute('aria-busy'),undefined);
  }
 }
 assert.match(page, /id="acme-configuration-status"[^>]*aria-live="polite"/);
 {
  const {context:c,get}=fixture();
  c.fetch=async()=>{throw Error('offline');};
  await c.loadSettingsPanel();
  const field=get('acme-email');
  field.value='draft@example.test';
  field.matches=()=>true;
  c.document.input({target:field});
  c.fetch=()=>assert.fail('Save submitted before saved settings were available');
  await get('btn-acme-settings-save').onclick();
  c.fetch=async()=>({ok:true,json:async()=>({acme_email:'saved@example.test',acme_staging:true})});
  await c.loadSettingsPanel();
  assert.equal(field.value,'draft@example.test');
  assert.equal(get('acme-staging').checked,true);
  assert.equal(c.cachedSettings.acme_email,'saved@example.test');
  let finish;
  c.fetch=()=>new Promise(resolve=>{finish=resolve;});
  const old=c.loadSettingsPanel();
  c.fetch=async()=>({ok:true,json:async()=>({acme_email:'latest@example.test',acme_staging:false})});
  await c.loadSettingsPanel();
  finish({ok:false});
  await old;
  assert.equal(c.cachedSettings.acme_email,'latest@example.test');
  assert.equal(field.value,'draft@example.test');
  get('cs-lapi-key').value='fixture';
  get('notify-telegram-token').value='fixture';
  c.clearSettingsDrafts();
  assert.equal(get('cs-lapi-key').value,'');
  assert.equal(get('notify-telegram-token').value,'');
  assert.equal(c.cachedSettings,null);
 }
 for (const scenario of ['missing','staging','missing_staging','production','offline','rejected','malformed','incomplete']) {
  const {context:c,get}=fixture();
  const settings={acme_email:scenario.startsWith('missing')?'':'ops@example.test',acme_staging:scenario==='staging'||scenario==='missing_staging'};
  let resolve;
  c.cachedSettings={acme_email:'old@example.test',acme_staging:false};
  c.fetch=async(path,init)=>{
   assert.equal(path,'/api/v1/settings');assert.equal(init.method,undefined);
   await new Promise(r=>{resolve=r});
   if(scenario==='offline')throw Error('offline');
   return {ok:scenario!=='rejected',json:async()=>{if(scenario==='malformed')throw Error('bad JSON');return scenario==='incomplete'?{}:settings}};
  };
  const loading=c.loadSettingsPanel();
  assert.match(get('acme-configuration-status').textContent,/unknown|not loaded/i);
  resolve();await loading;
  const status=get('acme-configuration-status');
  if(['offline','rejected','malformed','incomplete'].includes(scenario)) {
   assert.match(status.textContent,/unknown|not loaded/i);
   assert.equal(status.className,'warn');
   assert.match(get('certs-settings-msg').textContent,/could not load settings/i);
   assert.match(get('settings-msg').textContent,/could not load settings/i);
   continue;
  }
  assert.equal(get('acme-email').value,settings.acme_email);
  assert.equal(get('acme-staging').checked,settings.acme_staging);
  if(scenario.startsWith('missing'))assert.match(status.textContent,/issuance and renewal are paused.*email/i);
  if(settings.acme_staging)assert.match(status.textContent,/staging.*not.*trusted/i);
  if(scenario==='production') {assert.match(status.textContent,/production/i);assert.doesNotMatch(status.textContent,/healthy|running|paused/i);assert.equal(status.className,'dash-note');}
  else assert.equal(status.className,'warn');
  assert.doesNotMatch(status.textContent,/@|<script/);
 }
 for(const scenario of ['production','staging','missing','rejected','invalid']) {
  const {context:c,get}=fixture();
  c.cachedSettings={acme_email:'ops@example.test',acme_staging:true};
  c.renderACMEConfigurationStatus(c.cachedSettings);
  get('acme-email').value=' ops@example.test ';get('acme-staging').checked=false;
  if(scenario==='invalid')get('acme-email').checkValidity=()=>false;
  const persisted={acme_email:scenario==='missing'?'':'ops@example.test',acme_staging:scenario==='staging'};
  let calls=0;
  c.fetch=async(path,init)=>{calls++;assert.equal(path,'/api/v1/settings');assert.equal(init.method,'PATCH');
   assert.deepEqual(JSON.parse(init.body),{acme_email:'ops@example.test',acme_staging:false});
   return {ok:scenario!=='rejected',json:async()=>persisted,text:async()=> 'fixture rejection'};};
  await get('btn-acme-settings-save').onclick();
  if(scenario==='invalid') {assert.equal(calls,0);assert.match(get('certs-settings-msg').textContent,/valid email/i);continue;}
  assert.equal(calls,1);
  const status=get('acme-configuration-status');
  if(scenario==='rejected') {assert.match(get('certs-settings-msg').textContent,/fixture rejection/);assert.match(status.textContent,/staging/i);continue;}
  assert.equal(get('certs-settings-msg').textContent,'ACME saved.');
  assert.equal(get('certs-settings-msg').className,'ok');
  if(scenario==='missing')assert.match(status.textContent,/paused/i);
  else assert.match(status.textContent,scenario==='staging'?/staging/i:/production/i);
 }
}
run().catch(error=>{console.error(error);process.exitCode=1});
`
