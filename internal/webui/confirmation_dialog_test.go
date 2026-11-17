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

func TestConfirmationDialogs(t *testing.T) {
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
	cmd := exec.CommandContext(ctx, node, "-e", confirmationDialogTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("confirmation dialog: %v\n%s", err, output)
	}
}

const confirmationDialogTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const modalStart = page.indexOf('  function modalDialog(');
const modalEnd = page.indexOf('  function oneTimeCredentialDialog(', modalStart);
const confirmStart = page.indexOf('  function confirmDialog(');
const confirmEnd = page.indexOf('  async function withBusy(', confirmStart);
assert.ok(modalStart >= 0 && modalEnd > modalStart, 'missing modal primitive');
assert.ok(confirmStart >= 0 && confirmEnd > confirmStart, 'missing confirmation handler');
function setup() {
  const document = {activeElement: null};
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.events = {}; this.isConnected = true; this.disabled = false; this.id = ''; }
    appendChild(child) { this.children.push(child); }
    setAttribute(key, value) { this.attributes[key] = value; }
    addEventListener(key, fn) { this.events[key] = fn; }
    focus() { document.activeElement = this; }
    remove() { this.isConnected = false; }
  }
  document.createElement = tag => new Element(tag);
  document.body = new Element('body');
  const trigger = new Element('button'); trigger.focus();
  const context = vm.createContext({document});
  vm.runInContext('let modalSequence = 0;\n' + page.slice(modalStart, modalEnd) + page.slice(confirmStart, confirmEnd), context);
  return {document, trigger, context};
}
async function scenario(action, danger = true) {
  const {document, trigger, context} = setup();
  let settled = false;
  const promise = context.confirmDialog('Delete <fixture> & publication?', {danger, okLabel: 'Delete'})
    .then(result => {settled = true; return result;});
  const overlay = document.body.children[0], box = overlay.children[0];
  const title = box.children[0], message = box.children[1];
  const [cancel, ok] = box.children[3].children;
  assert.equal(document.activeElement, danger ? cancel : ok, 'initial focus');
  assert.equal(box.attributes.role, 'dialog');
  assert.equal(box.attributes['aria-modal'], 'true');
  assert.equal(box.attributes['aria-labelledby'], title.id);
  assert.equal(box.attributes['aria-describedby'], message.id);
  assert.equal(title.textContent, 'Confirm action');
  assert.equal(message.textContent, 'Delete <fixture> & publication?');
  function key(name, shiftKey = false) {
    const event = {key: name, shiftKey, prevented: false, stopped: false,
      preventDefault() {this.prevented = true}, stopPropagation() {this.stopped = true}};
    overlay.events.keydown(event); return event;
  }
  if (action === 'escape') {
    const event = key('Escape'); assert.ok(event.prevented && event.stopped);
  } else if (action === 'tab') {
    ok.focus(); assert.ok(key('Tab').prevented); assert.equal(document.activeElement, cancel);
    assert.ok(key('Tab', true).prevented); assert.equal(document.activeElement, ok);
    cancel.focus(); assert.equal(key('Tab').prevented, false);
    ok.focus(); assert.equal(key('Tab', true).prevented, false);
    assert.equal(key('x').prevented, false);
    await Promise.resolve(); assert.equal(settled, false, 'navigation must not submit');
    key('Escape');
  } else if (action === 'inside') {
    overlay.onclick({target: box}); await Promise.resolve(); assert.equal(settled, false);
    cancel.onclick();
  } else if (action === 'backdrop') { overlay.onclick({target: overlay});
  } else if (action === 'confirm') { ok.onclick(); cancel.onclick();
  } else if (action === 'detached') { trigger.isConnected = false; cancel.onclick();
  } else { cancel.onclick(); }
  assert.equal(await promise, action === 'confirm');
  assert.equal(overlay.isConnected, false);
  if (action === 'detached') assert.notEqual(document.activeElement, trigger);
  else assert.equal(document.activeElement, trigger, 'restore invoking control');
}
async function passwordScenario() {
  const {document, trigger, context} = setup();
  const promise = context.passwordDialog('Apply HAProxy configuration?');
  const box = document.body.children[0].children[0];
  const form = box.children[2].children[0];
  const input = form.children[0].children[0];
  const [cancel, ok] = box.children[3].children;
  assert.equal(document.activeElement, input);
  assert.equal(input.type, 'password');
  assert.equal(input.required, true);
  assert.equal(cancel.type, 'button');
  assert.equal(ok.type, 'submit');
  assert.ok(form.id, 'password form requires an id');
  assert.equal(ok.attributes.form, form.id, 'Confirm must submit its sibling form');
  input.value = 'fixture';
  let prevented = false;
  form.onsubmit({preventDefault() {prevented = true;}});
  assert.equal(await promise, 'fixture');
  assert.ok(prevented);
  assert.equal(document.activeElement, trigger);
}
(async () => {
  for (const action of ['escape', 'tab', 'inside', 'backdrop', 'confirm', 'cancel', 'detached']) await scenario(action);
  await scenario('escape', false);
  await passwordScenario();
})().catch(error => {console.error(error); process.exitCode = 1});
`
