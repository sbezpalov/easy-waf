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
)

func TestHighRiskDialogContract(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, forbidden := range []string{"window.prompt(", "if (!confirm("} {
		if strings.Contains(html, forbidden) {
			t.Errorf("native high-risk dialog remains: %q", forbidden)
		}
	}
	for _, want := range []string{
		"function oneTimeCredentialDialog(",
		"dismissible: false",
		"Hidden until revealed",
		"I saved it",
		"function confirmProtectiveRuleChange(",
		"'blacklist-add'",
		"'blacklist-delete'",
		"'allowlist-delete'",
		"'user-agent-delete'",
		"data-rule-value=",
		"function withFocusableBusy(",
		"return modalDialog({\n      title: 'SSH keys for '",
		"label.setAttribute('for', 'ssh-keys-editor')",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("high-risk dialog contract missing %q", want)
		}
	}
}

func TestHighRiskDialogInteraction(t *testing.T) {
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
	cmd := exec.CommandContext(ctx, node, "-e", highRiskDialogInteractionTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("high-risk dialog interaction: %v\n%s", err, output)
	}
}

const highRiskDialogInteractionTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
function source(from, to) {
  const start = page.indexOf(from), end = page.indexOf(to, start);
  assert.ok(start >= 0 && end > start, 'missing source ' + from);
  return page.slice(start, end);
}
const modalSource = source('  function modalDialog(', '  // Resolves to the password');
const credentialSource = source('  function oneTimeCredentialDialog(', '  const nativeFetch');
const protectiveSource = source('  function confirmProtectiveRuleChange(', '  async function withBusy(');
const busySource = source('  async function withFocusableBusy(', '  function statusBadge(');

class Element {
  constructor(tag) {
    this.tag = tag; this.children = []; this.attributes = {}; this.events = {};
    this.isConnected = true; this.disabled = false; this.id = ''; this.textContent = '';
    this.className = ''; this.style = {}; this.value = '';
  }
  appendChild(child) { this.children.push(child); }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  getAttribute(key) { return this.attributes[key]; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(key, fn) { this.events[key] = fn; }
  focus() { document.activeElement = this; }
  remove() { this.isConnected = false; }
}
const document = {activeElement: null, createElement: tag => new Element(tag), body: new Element('body')};
let copied = '';
const navigator = {clipboard: {writeText: async value => {copied = value}}};
const context = vm.createContext({document, navigator, console});
vm.runInContext('let modalSequence = 0;\n' + modalSource + credentialSource, context);

async function credentialScenario() {
  const trigger = new Element('button'); trigger.focus();
  let settled = false;
  const secret = 'Tmp-<not-html>-123';
  document.activeElement = document.body;
  const promise = context.oneTimeCredentialDialog('fixture<&user', secret, trigger).then(value => {settled = true; return value});
  const overlay = document.body.children.at(-1), box = overlay.children[0];
  const title = box.children[0], message = box.children[1], content = box.children[2], actions = box.children[3];
  const credentialBox = content.children[0], value = credentialBox.children[1], status = credentialBox.children[2];
  const [reveal, copy, saved] = actions.children;
  assert.equal(title.textContent, 'Temporary password created');
  assert.match(message.textContent, /fixture<&user/);
  assert.equal(value.textContent, 'Hidden until revealed');
  assert.equal(document.activeElement, reveal);
  assert.equal(box.attributes.role, 'dialog');

  const escape = {key: 'Escape', preventDefault() {this.prevented = true}, stopPropagation() {this.stopped = true}};
  overlay.events.keydown(escape);
  overlay.onclick({target: overlay});
  await Promise.resolve();
  assert.equal(settled, false, 'one-time credential must not close accidentally');
  assert.ok(escape.prevented && escape.stopped);

  reveal.onclick();
  assert.equal(value.textContent, secret);
  assert.equal(reveal.attributes['aria-pressed'], 'true');
  reveal.onclick();
  assert.equal(value.textContent, 'Hidden until revealed');
  await copy.onclick();
  assert.equal(copied, secret);
  assert.match(status.textContent, /Copied/);
  saved.onclick();
  assert.equal(await promise, true);
  assert.equal(value.textContent, '', 'secret must be cleared from detached DOM');
  assert.equal(overlay.isConnected, false);
  assert.equal(document.activeElement, trigger, 'focus returns to invoking control');
}

async function protectiveScenario() {
  const calls = [];
  const c = vm.createContext({confirmDialog: async (...args) => {calls.push(args); return true}, Promise});
  vm.runInContext(protectiveSource, c);
  const fixtures = [
    ['blacklist-add', '2001:db8::123', 'Blacklist client', 'Add to blacklist'],
    ['blacklist-delete', '198.51.100.0/24', 'Delete blacklist entry', 'Delete entry'],
    ['allowlist-delete', '10.0.0.0/8', 'Remove trusted allowlist entry', 'Remove entry'],
    ['user-agent-delete', '<script>scanner</script>', 'Delete blocked User-Agent pattern', 'Delete pattern']
  ];
  for (const [action, value, title, okLabel] of fixtures) {
    assert.equal(await c.confirmProtectiveRuleChange(action, value), true);
    const [message, options] = calls.at(-1);
    assert.match(message, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(message, /Apply HAProxy/);
    assert.match(message, /restore/i);
    assert.equal(options.title, title);
    assert.equal(options.okLabel, okLabel);
    assert.equal(options.danger, true);
  }
  assert.equal(await c.confirmProtectiveRuleChange('unknown', 'fixture'), false);
  assert.equal(calls.length, fixtures.length, 'unknown action must not open a dialog');
}

async function busyScenario() {
  const attrs = {};
  const button = {getAttribute: key => attrs[key], setAttribute: (key, value) => {attrs[key] = value}, removeAttribute: key => {delete attrs[key]}};
  let release, calls = 0;
  const gate = new Promise(resolve => {release = resolve});
  const c = vm.createContext({});
  vm.runInContext(busySource, c);
  const first = c.withFocusableBusy(button, async () => {calls++; await gate; return 'done'});
  await c.withFocusableBusy(button, async () => {calls++});
  assert.equal(calls, 1, 'busy action must not run twice');
  assert.equal(attrs['aria-busy'], 'true');
  release();
  assert.equal(await first, 'done');
  assert.equal(attrs['aria-busy'], undefined);
}

(async () => {
  await credentialScenario();
  await protectiveScenario();
  await busyScenario();
})().catch(error => {console.error(error); process.exitCode = 1});
`
