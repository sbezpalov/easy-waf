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

func TestAptBrowserStreamContract(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute browser APT stream regression tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"invalid_events", "missing_terminal", "terminal_without_eof",
		"fragmented_utf8", "record_limit", "reader_failure", "live_log_limit"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "-e", aptBrowserStreamTest, scenario)
			cmd.Stdin = bytes.NewReader(page)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("browser APT stream: %v\n%s", err, output)
			}
		})
	}
}

const aptBrowserStreamTest = `
const assert = require('node:assert/strict');
const vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const scenario = process.argv[1];
const timer = setTimeout(() => {console.error('unjoined browser stream: ' + scenario); process.exit(1)}, 8000);
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {textContent: '', className: '', dataset: {},
    style: {}, disabled: false, scrollHeight: 0, scrollTop: 0, clientHeight: 0});
  return elements.get(id);
};
const msg = element('sys-apt-msg'), out = element('sys-apt-output');
const notices = [], finished = [];
const context = {TextDecoder, document: {getElementById: element},
  toast: (...args) => notices.push(args), refreshAptPackageList: () => {},
  getTok: () => true, hdr: () => ({}), encodeURIComponent};
vm.createContext(context);
function include(from, until) {
  const start = page.indexOf(from), end = page.indexOf(until, start);
  assert.ok(start >= 0 && end > start, 'missing embedded region: ' + from);
  vm.runInContext(page.slice(start, end), context);
}
include('  let aptStatusRevision = 0;', '  async function loadSystemServicesTable(');
include('  let aptLogStickBottom = true;', '  async function refreshAptPackageList(');
include('  async function consumeAptStream(', "  document.getElementById('btn-sys-apt-clean').onclick");
const realFinish = context.finishAptStream, realReconnectFinish = context.finishAptStreamReconnect;
context.finishAptStream = (...args) => {finished.push(args); realFinish(...args)};
context.finishAptStreamReconnect = (...args) => {finished.push(args); realReconnectFinish(...args)};
const encoder = new TextEncoder();
const bytes = text => encoder.encode(text);
function response(chunks, close = true) {
  let canceled = 0, controller;
  const body = new ReadableStream({start(c) {
    controller = c;
    chunks.forEach(chunk => c.enqueue(typeof chunk === 'string' ? bytes(chunk) : chunk));
    if (close) c.close();
  }, cancel() {canceled++}});
  return {resp: {ok: true, body}, body, controller, canceled: () => canceled};
}
const exit = '{"type":"exit","code":0}\n';
const line = text => JSON.stringify({type: 'line', data: text}) + '\n';
function reset() {out.textContent = ''; msg.textContent = ''; msg.className = ''; notices.length = 0; finished.length = 0}
const cases = {
  async invalid_events() {
    for (const event of ['bad JSON', '[]', 'null', '{}', '{"type":"future"}',
        '{"type":"line","data":123}', '{"type":"line","data":null}',
        '{"type":"exit"}', '{"type":"exit","code":null}',
        '{"type":"exit","code":"0"}', '{"type":"exit","code":0.5}',
        '{"type":"exit","code":9007199254740992}',
        '{"type":"exit","code":0,"error":"capture failed"}',
        '{"type":"exit","code":0,"error":{}}']) {
      reset(); const fixture = response([event + '\n', exit]);
      await assert.rejects(() => context.consumeAptStream(fixture.resp), undefined, 'accepted event: ' + event);
      assert.equal(finished.length, 0, 'invalid event reached completion renderer');
      assert.equal(fixture.body.locked, false, 'invalid event retained reader lock');
      assert.equal(fixture.canceled(), 1, 'invalid event did not cancel unread body');
      assert.equal(notices.some(([, level]) => level === 'ok'), false);
    }
  },
  async missing_terminal() {
    for (const text of ['', line('Progress only'), '{"type":"exit","code":0}', line('ok') + '{"type":"exit"']) {
      reset(); const fixture = response([text]);
      context.fetch = async () => fixture.resp;
      const result = await context.runAptStream('/api/v1/host/updates/attach/stream?run_id=fixture', {reconnect: true});
      assert.equal(result.exitCode, -1, 'truncated stream reported success');
      assert.ok(result.exitErr, 'missing terminal has no unknown-outcome detail');
      assert.equal(msg.className, 'warn');
      assert.match(msg.textContent, /connection interrupted.*Refresh status/);
      assert.equal(notices.some(([, level]) => level === 'ok'), false);
      assert.equal(fixture.body.locked, false);
    }
  },
  async terminal_without_eof() {
    reset(); const fixture = response([line('Completed') + exit], false);
    const result = await context.consumeAptStream(fixture.resp);
    assert.equal(result.exitCode, 0);
    assert.equal(finished.length, 1); assert.equal(fixture.canceled(), 1);
    assert.equal(fixture.body.locked, false);
    assert.equal(out.textContent, 'Completed');
    // The first verified terminal result is authoritative, like the API relay.
    const again = response([exit + 'ignored trailing bytes']);
    assert.equal((await context.consumeAptStream(again.resp)).exitCode, 0);
  },
  async fragmented_utf8() {
    for (const code of [0, 100, -1]) {
      for (const error of ['', 'original failure']) {
        if (code === 0 && error) continue;
        reset();
        const text = 'Updates: café / 日本 / 😀';
        const all = bytes('\r\n' + line(text) + '{"type":"line","code":0}\n' +
          JSON.stringify({type: 'exit', code, ...(error ? {error} : {}), future: true}) + '\n');
        const fixture = response(Array.from(all, byte => Uint8Array.of(byte)));
        const result = await context.consumeAptStream(fixture.resp, {reconnect: true});
        assert.equal(result.exitCode, code);
        assert.equal(result.exitErr, error);
        assert.ok(out.textContent.includes(text));
        assert.equal(finished.length, 1); assert.equal(fixture.body.locked, false);
        if (code !== 0) {
          assert.equal(msg.className, 'warn');
          assert.match(msg.textContent, error ? /original failure/ : code === -1 ? /outcome.*unavailable.*saved.*log/ : /100/);
          assert.equal(notices.some(([, level]) => level === 'ok'), false);
        }
      }
    }
    reset(); const invalid = response([bytes('{"type":"line","data":"'), Uint8Array.of(0xc3, 0x28), bytes('"}\n' + exit)]);
    await assert.rejects(() => context.consumeAptStream(invalid.resp));
    assert.equal(finished.length, 0); assert.equal(invalid.body.locked, false);
  },
  async record_limit() {
    // Limit the original wire bytes across chunks, not only decoded UTF-16.
    for (const chunk of ['x'.repeat(1024 * 1024), 'é'.repeat(512 * 1024)]) {
      reset(); const fixture = response(Array(9).fill(bytes(chunk)), false);
      await assert.rejects(() => context.consumeAptStream(fixture.resp), /size limit/);
      assert.equal(finished.length, 0); assert.equal(fixture.body.locked, false);
      assert.equal(fixture.canceled(), 1);
    }
    const prefix = '{"type":"line","padding":"', suffix = '"}';
    const exact = prefix + 'x'.repeat(8 * 1024 * 1024 - prefix.length - suffix.length) + suffix + '\n';
    const boundary = response([exact, exit]);
    assert.equal((await context.consumeAptStream(boundary.resp)).exitCode, 0, 'exact wire limit rejected');
    // A real maximum worker line can expand sixfold in JSON escaping.
    reset(); const text = '\u0001'.repeat(1024 * 1024);
    const fixture = response([line(text), exit]);
    assert.equal((await context.consumeAptStream(fixture.resp)).exitCode, 0);
    assert.ok(out.textContent.endsWith(text));
    assert.equal(fixture.body.locked, false);
  },
  async reader_failure() {
    reset(); const fixture = response([], false);
    const pending = context.consumeAptStream(fixture.resp);
    fixture.controller.error(new Error('fixture reader disconnected'));
    await assert.rejects(() => pending, /fixture reader disconnected/);
    assert.equal(finished.length, 0); assert.equal(fixture.body.locked, false);
  },
  async live_log_limit() {
    reset(); const unit = 'Old line '.repeat(8192);
    for (let i = 0; i < 40; i++) context.appendAptLog(unit);
    context.appendAptLog('Newest package output');
    assert.ok(out.textContent.length <= 2 * 1024 * 1024, 'visible live log grows without a bound');
    assert.match(out.textContent, /^\[Earlier live log output omitted.*saved.*log.*\]/);
    assert.ok(out.textContent.endsWith('Newest package output'));
    // Cropping must not leave half of a UTF-16 surrogate pair at the boundary.
    context.appendAptLog('😀'.repeat(1024 * 1024));
    const tail = out.textContent.slice(out.textContent.indexOf('\n') + 1);
    assert.ok(!/^[\uDC00-\uDFFF]/.test(tail));
    assert.equal(out.textContent.includes('\ufffd'), false);
    assert.ok(out.textContent.length <= 2 * 1024 * 1024);
  }
};
(async () => {assert.ok(cases[scenario]); await cases[scenario](); clearTimeout(timer)})()
  .catch(err => {console.error(err); process.exit(1)});
`
