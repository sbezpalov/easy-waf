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

func TestApplicationVersionFeedback(t *testing.T) {
	runVersionUI(t, versionInteractionTest)
}

func TestAboutShowsVersionsAndAttribution(t *testing.T) {
	runVersionUI(t, aboutInteractionTest)
}

func runVersionUI(t *testing.T, script string) {
	t.Helper()
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
	cmd := exec.CommandContext(ctx, node, "-e", script)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("version UI interaction: %v\n%s", err, output)
	}
}

const versionInteractionTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  function renderApplicationVersion(');
const end = page.indexOf('  async function refreshSession(', start);
assert.ok(start >= 0 && end > start);
async function run() {
  for (const scenario of ['success', 'missing', 'malformed', 'rejected', 'offline']) {
    const elements = {'header-version': {textContent: 'vOLD'}, 'dash-version': {textContent: 'OLD'}};
    let calls = 0;
    const context = {document: {getElementById: id => elements[id]}, hdr: () => ({Authorization: 'fixture'}),
      fetch: async (path, init) => {
        calls++;
        assert.equal(path, '/api/v1/status');
        assert.equal(init.headers.Authorization, 'fixture');
        if (scenario === 'offline') throw Error('fixture network failure');
        return {ok: scenario !== 'rejected', json: async () => ({version:
          scenario === 'success' ? ' 9.8.7-rc.2 ' : scenario === 'malformed' ? {} : ''})};
      }};
    vm.createContext(context);
    vm.runInContext(page.slice(start, end), context);
    await context.loadApplicationVersion();
    assert.equal(calls, 1);
    assert.equal(elements['header-version'].textContent, scenario === 'success' ? 'v9.8.7-rc.2' : 'Version unavailable');
    assert.equal(elements['dash-version'].textContent, scenario === 'success' ? '9.8.7-rc.2' : 'Unknown');
  }
}
run().catch(error => {console.error(error); process.exitCode = 1});
`

const aboutInteractionTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
assert.ok(page.includes('href="#about"'));
assert.ok(page.includes("case 'about':\n        void loadAbout();"));
assert.ok(page.includes('Sergey Bezpalov and Easy Home WAF contributors'));
assert.ok(page.includes('<summary>Terms of use (Apache License 2.0)</summary>'));
const start = page.indexOf('  let aboutGeneration = 0;');
const end = page.indexOf('  const VIEWER_SAFE_ACTIONS', start);
assert.ok(start >= 0 && end > start);
function element() {
  return {
    textContent: '', children: [], hidden: false,
    appendChild(node) { this.children.push(node); },
    replaceChildren() { this.children = []; }
  };
}
async function run() {
  for (const scenario of ['success', 'no source date', 'offline']) {
    const elements = new Map();
    const context = {document: {getElementById: id => {
      if (!elements.has(id)) {
        const node = element();
        node.classList = {toggle: (cls, on) => { if (cls === 'hidden') node.hidden = on; }};
        elements.set(id, node);
      }
      return elements.get(id);
    }, createElement: element}, hdr: () => ({Authorization: 'fixture'}),
    fetch: async (path, init) => {
      assert.equal(path, '/api/v1/about');
      assert.equal(init.headers.Authorization, 'fixture');
      if (scenario === 'offline') throw Error('fixture network failure');
      return {ok: true, json: async () => ({
        version: '1.6.1', go_version: 'go1.27.4', platform: 'linux/amd64',
        revision: 'abc123', modified: true, license_text: 'Apache terms', notice: '<notice>',
        source_time: scenario === 'success' ? '2026-11-18T08:30:00Z' : undefined,
        components: [{name: 'HAProxy', version: '2.8.30', source: 'Installed package'},
          {name: 'PostgreSQL', source: 'Connected database'}]
      })};
    }};
    vm.createContext(context);
    vm.runInContext(page.slice(start, end), context);
    await context.loadAbout();
    if (scenario === 'offline') {
      assert.equal(elements.get('about-status').textContent, 'Could not load product information.');
      assert.equal(elements.get('about-components').children.length, 0);
      continue;
    }
    assert.equal(elements.get('about-status').textContent, '');
    assert.equal(elements.get('about-version').textContent, '1.6.1');
    assert.equal(elements.get('about-revision').textContent, 'abc123 (modified source)');
    const sourceTime = scenario === 'success' ? '2026-11-18T08:30:00Z' : '';
    assert.equal(elements.get('about-source-time').dateTime, sourceTime);
    assert.equal(elements.get('about-source-time').textContent, sourceTime);
    assert.equal(elements.get('about-source-time-row').hidden, !sourceTime);
    assert.equal(elements.get('about-license').textContent, 'Apache terms');
    assert.equal(elements.get('about-notice').textContent, '<notice>');
    assert.deepEqual(elements.get('about-components').children.map(row => row.children.map(cell => cell.textContent)), [
      ['HAProxy', '2.8.30', 'Installed package'], ['PostgreSQL', 'Unavailable', 'Connected database']
    ]);
  }
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
