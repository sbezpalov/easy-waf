// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import "testing"

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
}
run().catch(err=>{console.error(err);process.exitCode=1;});
`)
}
