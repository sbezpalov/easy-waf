// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import "testing"

func TestFail2banOverviewRecovery(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0,'utf8');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id,{addEventListener(){}});
  return elements.get(id);
}
const ctx = vm.createContext({document:{getElementById:element}, sessionGeneration:1,
  hdr:()=>({}),esc:String,tableState:(box,state)=>{box.innerHTML=state;},
  withFocusableBusy:(_,fn)=>fn()});
const start = page.indexOf('  let fail2banGeneration');
const end = page.indexOf("  document.getElementById('btn-cs-ping').onclick", start);
assert.ok(start>=0 && end>start);
vm.runInContext(page.slice(start,end),ctx);
const data = (rows,running=true)=>Response.json({status:{running},jails:rows});
const rows=[{name:'sshd',banned_ips:[]},{name:'missing',unavailable:true}];
async function run() {
  const select=element('f2b-unban-jail'), button=element('btn-f2b-unban'), table=element('f2b-jails-wrap');
  ctx.fetch=async()=>data(rows);
  await ctx.loadFail2banOverview();
  assert.equal(button.disabled,false);
  assert.match(select.innerHTML,/sshd/);
  assert.doesNotMatch(select.innerHTML,/missing/);
  assert.match(table.innerHTML,/Unavailable/);
  let finish,approve;
  ctx.confirmDialog=()=>new Promise(resolve=>{approve=resolve;});
  const pending=ctx.confirmFail2banUnban(button,'sshd','203.0.113.1');
  ctx.fetch=()=>new Promise(resolve=>{finish=resolve;});
  const old=ctx.loadFail2banOverview();
  assert.equal(select.disabled,true);
  assert.doesNotMatch(select.innerHTML,/sshd/);
  let calls=0;
  ctx.fetch=async()=>{calls++;throw new Error('offline');};
  await ctx.loadFail2banOverview();
  approve(true);
  assert.equal(await pending,false);
  assert.equal(calls,1);
  finish(data(rows));
  await old;
  assert.equal(button.disabled,true);
  assert.equal(table.innerHTML,'error');
  assert.match(element('f2b-status-msg').textContent,/Refresh jails/);
  for(const response of [data([]),data(rows,false),Response.json({})]){
    ctx.fetch=async()=>response;
    await ctx.loadFail2banOverview();
    assert.equal(button.disabled,true);
  }
  ctx.fetch=async()=>data(rows);
  await ctx.loadFail2banOverview();
  assert.equal(select.disabled,false);
  assert.equal(button.disabled,false);
}
run().catch(error=>{console.error(error);process.exitCode=1});
`)
}
