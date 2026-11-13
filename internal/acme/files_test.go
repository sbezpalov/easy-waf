// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func TestOrphanCertificatesHaveIndependentPrivateDirectories(t *testing.T) {
	state := t.TempDir()
	const attempts = 12
	type result struct {
		dir      string
		err      error
		resource *certificate.Resource
	}
	results := make(chan result, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range attempts {
		res, err := issueTestResource()
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			<-start
			dir, err := SaveOrphanCertificateResource(state, "test-cert", res)
			results <- result{dir: dir, err: err, resource: res}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for got := range results {
		if got.err != nil {
			t.Error(got.err)
			continue
		}
		if seen[got.dir] {
			t.Error("independent results share a recovery directory")
		}
		seen[got.dir] = true
		chain, err := os.ReadFile(filepath.Join(got.dir, "fullchain.pem"))
		if err != nil || !bytes.Equal(chain, got.resource.Certificate) {
			t.Error("recovery certificate was replaced")
		}
		key, err := os.ReadFile(filepath.Join(got.dir, "privkey.pem"))
		if err != nil || !bytes.Equal(key, got.resource.PrivateKey) {
			t.Error("recovery private key was replaced")
		}
		if _, err := tls.X509KeyPair(chain, key); err != nil {
			t.Error("recovery pair is mismatched")
		}
		if runtime.GOOS != "windows" {
			for path, want := range map[string]os.FileMode{got.dir: 0o700, filepath.Join(got.dir, "fullchain.pem"): 0o600, filepath.Join(got.dir, "privkey.pem"): 0o600} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != want {
					t.Error("recovery material permissions are not private")
				}
			}
		}
	}
}

func TestWriteCertificateResourceRejectsTraversalID(t *testing.T) {
	_, _, _, _, err := WriteCertificateResource(t.TempDir(), "../../acme/webroot/.well-known/acme-challenge", &certificate.Resource{})
	if err == nil || !strings.Contains(err.Error(), "certificate id") {
		t.Fatalf("expected certificate id error, got %v", err)
	}
}

func TestCertificateGenerationsPreservePreviousPairs(t *testing.T) {
	state := t.TempDir()
	parent := filepath.Join(state, "certs", "test-cert")
	if err := os.MkdirAll(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	old, err := issueTestResource()
	if err != nil {
		t.Fatal(err)
	}
	legacyFull := filepath.Join(parent, "fullchain.pem")
	legacyKey := filepath.Join(parent, "privkey.pem")
	if err := os.WriteFile(legacyFull, old.Certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyKey, old.PrivateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	var previousFull, previousKey string
	for range 2 {
		res, err := issueTestResource()
		if err != nil {
			t.Fatal(err)
		}
		full, key, nb, na, err := WriteCertificateResource(state, "test-cert", res)
		if err != nil {
			t.Fatal(err)
		}
		if full == previousFull || key == previousKey || full == legacyFull || key == legacyKey || !na.After(nb) {
			t.Fatal("renewal reused a previous pair or invalid validity")
		}
		if filepath.Dir(full) != filepath.Dir(key) || !strings.HasPrefix(filepath.Base(filepath.Dir(full)), "generation-") {
			t.Fatal("pair is not in one private generation")
		}
		certBytes, err := os.ReadFile(full)
		if err != nil || !bytes.Equal(certBytes, res.Certificate) {
			t.Fatal("complete certificate not published before return")
		}
		keyBytes, err := os.ReadFile(key)
		if err != nil || !bytes.Equal(keyBytes, res.PrivateKey) {
			t.Fatal("complete private key not published before return")
		}
		if _, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
			t.Fatal("generation is not a matching key pair")
		}
		if previousFull != "" {
			previousCert, err := os.ReadFile(previousFull)
			if err != nil {
				t.Fatal(err)
			}
			previousPrivate, err := os.ReadFile(previousKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tls.X509KeyPair(previousCert, previousPrivate); err != nil {
				t.Fatal("renewal damaged the preceding generation")
			}
		}
		if runtime.GOOS != "windows" {
			for path, mode := range map[string]os.FileMode{full: 0o600, key: 0o600, filepath.Dir(full): 0o700} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("private generation permissions: %v", err)
				}
			}
		}
		previousFull, previousKey = full, key
	}
	for path, want := range map[string][]byte{legacyFull: old.Certificate, legacyKey: old.PrivateKey} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("legacy certificate pair changed before DB publication")
		}
	}
}

func TestCertificateGenerationRejectsInvalidPairWithoutWrites(t *testing.T) {
	res, err := issueTestResource()
	if err != nil {
		t.Fatal(err)
	}
	other, err := issueTestResource()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	for _, invalid := range []*certificate.Resource{nil, {}, {Certificate: res.Certificate, PrivateKey: other.PrivateKey}, {Certificate: []byte("partial certificate"), PrivateKey: res.PrivateKey}} {
		if _, _, _, _, err := WriteCertificateResource(state, "test-cert", invalid); err == nil {
			t.Fatal("invalid resource accepted")
		}
		if _, err := SaveOrphanCertificateResource(state, "test-cert", invalid); err == nil {
			t.Fatal("invalid recovery resource accepted")
		}
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid resource touched state")
	}
	blocked := filepath.Join(state, "blocked")
	if err := os.WriteFile(blocked, []byte("regular file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := WriteCertificateResource(blocked, "test-cert", res); err == nil {
		t.Fatal("write under a regular file succeeded")
	}
}
