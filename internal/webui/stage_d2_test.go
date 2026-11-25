// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"strings"
	"testing"
)

func TestStageD2BackupRestoreDisclosureHasNoFakeAction(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	start := strings.Index(html, `<section class="panel" id="system-backup-restore"`)
	if start < 0 {
		t.Fatal("backup and restore disclosure is missing")
	}
	end := strings.Index(html[start:], `</section>`)
	if end < 0 {
		t.Fatal("backup and restore disclosure is not closed")
	}
	section := html[start : start+end]
	for _, want := range []string{
		"not available in the web panel",
		"sudo easy-waf-backup --dir /var/backups/easy-waf --keep 7",
		"sudo easy-waf-restore /path/to/easy-waf-backup-YYYYMMDD-HHMMSS.tar.gz",
		`href="/help/backup-restore.txt"`,
		"/usr/share/doc/easy-waf/BACKUP_RESTORE.md",
		"Restore replaces the database and appliance state",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("backup and restore disclosure missing %q", want)
		}
	}
	if strings.Contains(section, "<button") || strings.Contains(section, "fetch(") {
		t.Fatal("backup and restore disclosure must not imply an unsupported GUI action")
	}
}

func TestStageD2MobilePrimaryTargetsAndErrorsRemainActionable(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`.nav-toggle, .header-logout, .modal-actions button, .app-content button:not(.secondary) { min-height: var(--touch-target); }`,
		`const ms = k === 'err' ? 0 : (timeoutMs == null ? 5000 : timeoutMs);`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Stage D2 interaction contract missing %q", want)
		}
	}
}

func TestMobileNavigationFocus(t *testing.T) {
	runVersionUI(t, `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0,'utf8');
const nodes = new Map();
const bodyClasses = new Set();
const document = {body:{classList:{add:k=>bodyClasses.add(k),remove:k=>bodyClasses.delete(k),contains:k=>bodyClasses.has(k)}},
  addEventListener(name,fn){this[name]=fn;},getElementById:id=>node(id),
  querySelector:sel=>node(sel.includes('aria-current')?'current':'first')};
function node(id) {
  if (!nodes.has(id)) nodes.set(id,{setAttribute(k,v){this[k]=v;},focus(){document.activeElement=this;},
    getClientRects(){return this.hidden?[]:[{}];},contains(el){return el===node('current');}});
  return nodes.get(id);
}
let resize;
const window={matchMedia:()=>({addEventListener:(event,fn)=>{resize=fn;}})};
const ctx=vm.createContext({document,window});
function include(a,b){
  const start=page.indexOf(a),end=page.indexOf(b,start);
  assert.ok(start>=0 && end>start);
  vm.runInContext(page.slice(start,end),ctx);
}
include('  function openMobileNav()', '  function showTabFromHash()');
include("  document.getElementById('nav-toggle').onclick", "  window.addEventListener('hashchange'");
const toggle=node('nav-toggle'),main=node('main-content');
toggle.onclick();
assert.equal(document.activeElement,node('current'));
assert.equal(main.inert,true);
document.keydown({key:'Escape',preventDefault(){}});
assert.equal(document.activeElement,toggle);
assert.equal(main.inert,false);
assert.equal(toggle['aria-expanded'],'false');
node('current').hidden=true;
toggle.onclick();
assert.equal(document.activeElement,node('first'));
node('sidebar-nav').onclick({target:{closest:()=>true}});
assert.equal(document.activeElement,main);
toggle.onclick();
resize({matches:false});
assert.equal(main.inert,false);
assert.equal(bodyClasses.has('nav-open'),false);
node('current').focus();
resize({matches:true});
assert.equal(document.activeElement,toggle);
`)
}
