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

func TestSharedLeafRenderers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute renderer regression tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", sharedLeafRenderersTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shared leaf renderers: %v\n%s", err, output)
	}
}

const sharedLeafRenderersTest = `
const assert = require('node:assert/strict');
const vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  function statusBadge(');
const end = page.indexOf('  function markPendingApply(', start);
assert.ok(start >= 0 && end > start, 'shared leaf renderer region is missing');
const esc = value => String(value)
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
const context = vm.createContext({esc});
vm.runInContext(page.slice(start, end), context);

assert.equal(context.statusBadge('<Ready>', 'success'),
  '<span class="status-badge status-badge-success">&lt;Ready&gt;</span>');
assert.equal(context.statusBadge('State', 'invalid'),
  '<span class="status-badge status-badge-unknown">State</span>');
assert.equal(context.alertView('warning', '<Title>', 'A & B'),
  '<div class="alert alert-warning"><strong class="alert-title">&lt;Title&gt;</strong><p>A &amp; B</p></div>');
assert.equal(context.stateView('', ''),
  '<div class="state-view" data-state="unknown">Unavailable</div>');

const box = {};
context.tableState(box, 'loading', {message: '<Wait>'});
assert.equal(box.innerHTML, '<p class="table-state">&lt;Wait&gt;</p>');
context.tableState(box, 'empty');
assert.equal(box.innerHTML, '<p class="table-state dash-note">No data.</p>');
context.tableState(box, 'error', {message: 'A & B'});
assert.equal(box.innerHTML, '<p class="table-state warn">A &amp; B</p>');
assert.doesNotThrow(() => context.tableState(null, 'loading'));
`
