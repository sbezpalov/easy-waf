// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/systemdallow"
)

func TestScopedJournalUIContract(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`class="panel admin-only" id="host-journal-panel"`,
		`id="host-journal-unit"`,
		`id="host-journal-since"`,
		`id="host-journal-priority"`,
		`id="host-journal-lines"`,
		`id="host-journal-output" class="journal-output" tabindex="0"`,
		`The browser cannot request arbitrary units or journalctl flags.`,
		`/api/v1/host/journal?`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("scoped journal UI missing %q", want)
		}
	}
	unitStart := strings.Index(html, `id="host-journal-unit"`)
	if unitStart < 0 {
		t.Fatal("journal unit select is missing")
	}
	unitEnd := strings.Index(html[unitStart:], `</select>`)
	if unitEnd < 0 {
		t.Fatal("journal unit select is incomplete")
	}
	unitSelect := html[unitStart : unitStart+unitEnd]
	for _, unit := range systemdallow.AllowedUnits {
		if !strings.Contains(unitSelect, `option value="`+unit+`"`) {
			t.Errorf("journal allowlisted unit missing %q", unit)
		}
	}
	if got, want := strings.Count(unitSelect, `<option value="`), len(systemdallow.AllowedUnits); got != want {
		t.Errorf("journal unit options = %d, want exactly %d allowlisted units", got, want)
	}
	if strings.Contains(html, `input id="host-journal-unit"`) {
		t.Fatal("journal unit must not be free-form input")
	}
}

func TestScopedJournalUIInteraction(t *testing.T) {
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
	cmd := exec.CommandContext(ctx, node, "-e", scopedJournalInteractionTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scoped journal interaction: %v\n%s", err, output)
	}
}

const scopedJournalInteractionTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  let hostJournalGen = 0;');
const end = page.indexOf('  function blockedRuleLabel(', start);
assert.ok(start >= 0 && end > start, 'missing scoped journal functions');

function makeOutput() {
  const attrs = {};
  return {textContent: 'Not loaded.', set innerHTML(_) {throw Error('journal output must use textContent')},
    setAttribute: (name, value) => {attrs[name] = value}, removeAttribute: name => {delete attrs[name]},
    getAttribute: name => attrs[name]};
}
function response(body, status = 200) {
  return {ok: status >= 200 && status < 300, status,
    text: async () => typeof body === 'string' ? body : JSON.stringify(body)};
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, fail) => {resolve = ok; reject = fail});
  return {promise, resolve, reject};
}

async function run() {
  const elements = {
    'host-journal-unit': {value: 'haproxy.service'},
    'host-journal-since': {value: '1h'},
    'host-journal-priority': {value: 'warning'},
    'host-journal-lines': {value: '200'},
    'btn-host-journal-load': {setAttribute: (name, value) => {elements['btn-host-journal-load'].attrs[name] = value},
      removeAttribute: name => {delete elements['btn-host-journal-load'].attrs[name]},
      getAttribute: name => elements['btn-host-journal-load'].attrs[name], attrs: {}},
    'host-journal-output': makeOutput(),
    'host-journal-status': {textContent: ''}
  };
  let calls = [], gate = deferred();
  const context = {console, URLSearchParams,
    document: {getElementById: id => elements[id]}, panelFromHash: () => 'logs', hdr: () => ({Authorization: 'fixture'}),
    fetch: path => {calls.push(path); return gate.promise}};
  vm.createContext(context);
  vm.runInContext(page.slice(start, end), context);

  const first = context.loadHostJournal();
  assert.equal(elements['btn-host-journal-load'].getAttribute('aria-busy'), 'true', 'duplicate request must be blocked');
  await context.loadHostJournal();
  assert.equal(calls.length, 1, 'busy journal load must not start a duplicate request');
  assert.equal(elements['host-journal-output'].getAttribute('aria-busy'), 'true');
  assert.equal(elements['host-journal-output'].textContent, 'Not loaded.', 'previous snapshot stays visible while loading');
  gate.resolve(response({log: '<img src=x onerror=alert(1)>\nsecond line\n'}));
  await first;
  assert.equal(calls[0], '/api/v1/host/journal?unit=haproxy.service&since=1h&lines=200&priority=warning');
  assert.equal(elements['host-journal-output'].textContent, '<img src=x onerror=alert(1)>\nsecond line\n');
  assert.equal(elements['host-journal-output'].getAttribute('aria-busy'), undefined);
  assert.match(elements['host-journal-status'].textContent, /Loaded 2 lines from haproxy\.service/);

  gate = deferred();
  elements['host-journal-priority'].value = '';
  const empty = context.loadHostJournal();
  gate.resolve(response({log: ''}));
  await empty;
  assert.equal(elements['host-journal-output'].textContent, 'No journal entries matched these filters.');
  assert.match(elements['host-journal-status'].textContent, /no matching entries/);

  gate = deferred();
  const rejected = context.loadHostJournal();
  gate.resolve(response({error: 'journal unavailable'}, 500));
  await rejected;
  assert.equal(elements['host-journal-output'].textContent, 'Journal unavailable.');
  assert.equal(elements['host-journal-status'].textContent, 'journal unavailable');

  context.fetch = async () => {throw Error('private network detail')};
  await context.loadHostJournal();
  assert.equal(elements['host-journal-output'].textContent, 'Journal unavailable.');
  assert.match(elements['host-journal-status'].textContent, /API is unavailable/);
  assert.doesNotMatch(elements['host-journal-status'].textContent, /private/);

  gate = deferred();
  context.fetch = path => {calls.push(path); return gate.promise};
  const stale = context.loadHostJournal();
  elements['host-journal-unit'].value = 'postgresql.service';
  context.markHostJournalFiltersChanged();
  assert.equal(elements['btn-host-journal-load'].getAttribute('aria-busy'), undefined);
  assert.match(elements['host-journal-status'].textContent, /Filters changed/);
  gate.resolve(response({log: 'stale response'}));
  await stale;
  assert.notEqual(elements['host-journal-output'].textContent, 'stale response');

  elements['host-journal-output'].textContent = 'private previous-admin journal';
  context.clearHostJournalSnapshot('Administrator access is required.');
  assert.equal(elements['host-journal-output'].textContent, 'Not loaded.');
  assert.equal(elements['host-journal-status'].textContent, 'Administrator access is required.');
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
