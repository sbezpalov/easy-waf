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

func TestRevisionRollbackFeedback(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for UI interaction tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "rejected", "cancelled", "refresh_failed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "-e", revisionFeedbackTest, scenario)
			cmd.Stdin = bytes.NewReader(page)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("revision feedback: %v\n%s", err, output)
			}
		})
	}
}

const revisionFeedbackTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8'), scenario = process.argv[1];
const elements = new Map(), calls = [], notices = [], confirmations = [], tableStates = [];
const button = {getAttribute: name => name === 'data-id' ? '23' : 'abcdef0123456789'};
function element(id) {
  if (!elements.has(id)) elements.set(id, {textContent: '', className: '', innerHTML: '',
    querySelectorAll: () => [button]});
  return elements.get(id);
}
let lists = 0, pending = null, edgeRefreshes = 0;
const context = {document: {getElementById: element}, hdr: () => ({}), encodeURIComponent,
  esc: text => String(text), formatHostTime: String, shortSha: text => String(text).slice(0, 12), copyBtn: () => '',
  tableState: (_box, state) => tableStates.push(state), refreshSession: () => {throw Error('unexpected auth refresh')},
  toast: (...args) => notices.push(args), markPendingApply: on => {pending = on},
  refreshEdgeStatus: async () => {edgeRefreshes++; pending = null},
  confirmDialog: async (...args) => {confirmations.push(args); return scenario !== 'cancelled'},
  apiMessage: async response => response.kind === 'list' ? 'Revision list unavailable' : 'Rollback failed',
  fetch: async (path, init) => {
    calls.push([path, init]);
    if (path === '/api/v1/revisions?limit=50') {
      lists++;
      return {kind: 'list', ok: !(scenario === 'refresh_failed' && lists > 1), status: 200,
        json: async () => [{id: 23, sha: 'abcdef0123456789', is_current: false}]};
    }
    assert.equal(path, '/api/v1/revisions/23/rollback');
    assert.equal(init.method, 'POST');
    return {kind: 'rollback', ok: scenario !== 'rejected'};
  }};
vm.createContext(context);
const start = page.indexOf('  async function loadRevisions(');
const end = page.indexOf('  let cachedSettings =', start);
assert.ok(start >= 0 && end > start, 'missing revision interaction');
vm.runInContext(page.slice(start, end), context);
async function run() {
  await context.loadRevisions();
  const message = element('revisions-msg');
  await button.onclick();
  // Drain the old handler's unawaited refresh too: it must not erase the result.
  for (let i = 0; i < 5; i++) await Promise.resolve();
  const mutations = calls.filter(([path]) => path.endsWith('/rollback'));
  if (scenario === 'cancelled') {
    assert.equal(mutations.length, 0); assert.equal(lists, 1); assert.equal(pending, null); assert.equal(edgeRefreshes, 0);
    assert.equal(notices.length, 0);
    return;
  }
  assert.equal(mutations.length, 1);
  assert.equal(lists, 2, 'refresh revision list after operation');
  if (scenario === 'rejected') {
    assert.equal(message.textContent, 'Rollback failed', 'rejection must survive list refresh');
    assert.equal(message.className, 'warn'); assert.equal(pending, null); assert.equal(edgeRefreshes, 0);
    assert.ok(notices.some(([, kind]) => kind === 'err'));
  } else {
    assert.match(message.textContent, /restored/i, 'success must survive list refresh');
    assert.match(message.textContent, /saved applications and settings/i);
    assert.match(message.textContent, /unknown/i);
    assert.equal(pending, null, 'rollback must not claim which saved generation is applied');
    assert.equal(edgeRefreshes, 1, 'rollback must refresh persistent edge truth');
    assert.ok(notices.some(([, kind]) => kind === 'ok'));
    if (scenario === 'refresh_failed') assert.equal(tableStates.at(-1), 'error');
  }
  const [prompt, options] = confirmations[0];
  assert.match(prompt, /saved applications and settings/i);
  assert.match(prompt, /Apply.*restart/i);
  assert.equal(options.danger, true);
  await element('btn-revisions-refresh').onclick();
  for (let i = 0; i < 5; i++) await Promise.resolve();
  assert.equal(message.textContent, '', 'manual refresh clears old operation feedback');
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
