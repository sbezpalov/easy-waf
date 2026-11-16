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
	cmd := exec.CommandContext(ctx, node, "-e", versionInteractionTest)
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
    assert.equal(elements['dash-version'].textContent, scenario === 'success' ? '9.8.7-rc.2' : '—');
  }
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
