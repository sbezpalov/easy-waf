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
 const get = id => elements[id] ||= {textContent:'',className:'',value:'',checked:false};
 const context = {document:{getElementById:get},cachedSettings:null,hdr:()=>({}),
  loadIpwlToggleFromSettings(){},loadBotProtectionFromSettings(){},loadEdgeNetworkFromSettings(){},
  loadGeoIPFromSettings(){},loadIpblFetchCIDRsFromSettings(){}};
 vm.createContext(context);
 include(context, '  function renderACMEConfigurationStatus(', '  async function loadSettingsPanel(');
 include(context, '  async function loadSettingsPanel(', '  function loadIpwlToggleFromSettings(');
 include(context, "  document.getElementById('btn-acme-settings-save').onclick", "  document.getElementById('btn-cs-settings-save').onclick");
 return {context,get};
}
async function run() {
 assert.match(page, /id="acme-configuration-status"[^>]*aria-live="polite"/);
 for (const scenario of ['missing','staging','missing_staging','production','offline','rejected','malformed']) {
  const {context:c,get}=fixture();
  const settings={acme_email:scenario.startsWith('missing')?'':'ops@example.test',acme_staging:scenario==='staging'||scenario==='missing_staging'};
  let resolve;
  c.cachedSettings={acme_email:'old@example.test',acme_staging:false};
  c.fetch=async(path,init)=>{
   assert.equal(path,'/api/v1/settings');assert.equal(init.method,undefined);
   await new Promise(r=>{resolve=r});
   if(scenario==='offline')throw Error('offline');
   return {ok:scenario!=='rejected',json:async()=>{if(scenario==='malformed')throw Error('bad JSON');return settings}};
  };
  const loading=c.loadSettingsPanel();
  assert.match(get('acme-configuration-status').textContent,/unknown|not loaded/i);
  resolve();await loading;
  const status=get('acme-configuration-status');
  if(['offline','rejected','malformed'].includes(scenario)) {
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
 for(const scenario of ['production','staging','missing','rejected']) {
  const {context:c,get}=fixture();
  c.cachedSettings={acme_email:'ops@example.test',acme_staging:true};
  c.renderACMEConfigurationStatus(c.cachedSettings);
  get('acme-email').value=' ops@example.test ';get('acme-staging').checked=false;
  const persisted={acme_email:scenario==='missing'?'':'ops@example.test',acme_staging:scenario==='staging'};
  let calls=0;
  c.fetch=async(path,init)=>{calls++;assert.equal(path,'/api/v1/settings');assert.equal(init.method,'PATCH');
   assert.deepEqual(JSON.parse(init.body),{acme_email:'ops@example.test',acme_staging:false});
   return {ok:scenario!=='rejected',json:async()=>persisted,text:async()=> 'fixture rejection'};};
  await get('btn-acme-settings-save').onclick();assert.equal(calls,1);
  const status=get('acme-configuration-status');
  if(scenario==='rejected') {assert.match(get('certs-settings-msg').textContent,/fixture rejection/);assert.match(status.textContent,/staging/i);continue;}
  assert.equal(get('certs-settings-msg').textContent,'ACME saved.');
  assert.equal(get('certs-settings-msg').className,'ok');
  if(scenario==='missing')assert.match(status.textContent,/paused/i);
  else assert.match(status.textContent,scenario==='staging'?/staging/i:/production/i);
 }
 console.log('PASS: 7 settings-load and 4 ACME-save scenarios');
}
run().catch(error=>{console.error(error);process.exitCode=1});
`
