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

func TestPublicationFlowStructure(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`id="publication-routing-title"`,
		`id="publication-tls-title"`,
		`id="publication-protection-title"`,
		`id="publication-review-title"`,
		`id="apps-form-error" role="alert"`,
		`id="app-advanced"`,
		`id="app-cert-create-panel"`,
		`id="app-publication-review"`,
		`Create certificate &amp; request issuance`,
		`Application is not saved until the certificate is ready.`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("publication flow missing %q", want)
		}
	}
	for _, id := range []string{"name", "host", "backend", "port", "listen-mode", "app-cert", "profile", "app-security-mode", "app-health-path"} {
		if !strings.Contains(html, `for="`+id+`"`) {
			t.Errorf("publication field %q has no persistent label", id)
		}
	}
}

func TestPublicationFlowInteractions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for publication-flow interaction tests")
	}
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", publicationFlowTest)
	cmd.Stdin = bytes.NewReader(page)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("publication flow failed: %v; output: %s", err, output)
	}
}

const publicationFlowTest = `
const assert = require('node:assert/strict'), vm = require('node:vm');
const page = require('node:fs').readFileSync(0, 'utf8');
const start = page.indexOf('  let appCertificatesCache =');
const end = page.indexOf('  function appModeCardClass(', start);
assert.ok(start >= 0 && end > start, 'missing publication certificate helpers');

function element(value = '') {
  const classes = new Set();
  return {value, checked: false, disabled: false, textContent: '', innerHTML: '', options: [],
    dataset: {}, focus() {this.focused = true},
    classList: {add: x => classes.add(x), remove: x => classes.delete(x),
      toggle: (x, on) => on ? classes.add(x) : classes.delete(x), contains: x => classes.has(x)}};
}

async function run() {
  const elements = {
    'app-cert': element(''), 'app-cert-status': element(), 'save': element(),
    'listen-mode': element('https_only'), 'app-cert-domain': element('app.example.com'),
    'app-cert-mode': element('http-01'), 'app-cert-dns-provider': element(''),
    'app-cert-dns-env': element(''), 'app-cert-fullchain': element(''),
    'app-cert-key': element(''), 'app-cert-staging': element(),
    'app-cert-create-status': element(), 'app-cert-create-panel': element(),
    'app-cert-dns-fields': element(), 'app-cert-manual-fields': element(),
    'app-publication-review': element(), 'apps-form-error': element()
  };
  elements['app-cert-staging'].checked = true;
  const calls = [];
  const context = {console, document: {getElementById: id => elements[id]},
    hdr: () => ({}), esc: String, apiMessage: async r => 'HTTP ' + r.status,
    fetch: async (path, init) => {
      calls.push([path, init]);
      if (path === '/api/v1/certificates' && init && init.method === 'POST') {
        return {ok: true, status: 200, json: async () => ({id: 'cert-1', primary_domain: 'app.example.com',
          mode: 'http-01', acme_status: 'ready'})};
      }
      if (path === '/api/v1/certificates/cert-1/request-issue') {
        return {ok: true, status: 200, json: async () => ({id: 'cert-1', primary_domain: 'app.example.com',
          mode: 'http-01', acme_status: 'pending'})};
      }
      if (path === '/api/v1/certificates') {
        return {ok: true, status: 200, json: async () => [{id: 'cert-1', primary_domain: 'app.example.com',
          mode: 'http-01', acme_status: 'pending'}]};
      }
      throw Error('unexpected request ' + path);
    }};
  vm.createContext(context);
  vm.runInContext(page.slice(start, end), context);

  assert.equal(context.certificatePublicationState({acme_status: 'ready',
    fullchain_path: '/cert/fullchain.pem', pem_key_path: '/cert/key.pem'}), 'ready');
  assert.equal(context.certificatePublicationState({acme_status: 'pending'}), 'pending');
  assert.equal(context.certificatePublicationState({acme_status: 'failed'}), 'failed');
  assert.equal(context.certificatePublicationState({acme_status: 'ready'}), 'unavailable');

  const invalid = context.validatePublicationBasics({
    name: '', public_host: 'Bad Host', backend_host: '', backend_port: 0,
    listen_mode: 'https_only', certificate_id: ''
  }, null);
  assert.deepEqual(Object.keys(invalid).sort(), ['backend', 'certificate', 'host', 'name', 'port']);

  await context.createPublicationCertificate();
  assert.equal(calls[0][0], '/api/v1/certificates');
  assert.equal(JSON.parse(calls[0][1].body).primary_domain, 'app.example.com');
  assert.equal(calls[1][0], '/api/v1/certificates/cert-1/request-issue');
  assert.equal(calls[2][0], '/api/v1/certificates');
  assert.equal(elements['app-cert'].value, 'cert-1');
  assert.match(elements['app-cert-create-status'].textContent, /pending|requested/i);
  assert.match(elements['app-cert-status'].textContent, /not saved|pending/i);

  context.fetch = async () => { throw Error('offline') };
  await context.loadCertOptionsForApps();
  assert.equal(elements['app-cert-status'].dataset.state, 'unavailable');
  assert.match(elements['app-cert-status'].textContent, /unavailable/i);
}
run().catch(error => {console.error(error); process.exitCode = 1});
`
