// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/easy-waf/easy-waf/internal/haproxy"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCrtListCertPaths(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "crt-list.txt")
	writeFile(t, list, "# header\n/a/bundle.pem alpn h2,http/1.1\n\n/b/bundle.pem alpn h2,http/1.1\n")
	got, err := crtListCertPaths(list)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/a/bundle.pem", "/b/bundle.pem"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got, err := crtListCertPaths(filepath.Join(dir, "missing")); err != nil || got != nil {
		t.Fatalf("missing crt-list: %v %v", got, err)
	}
}

// A certificate renewed in place (same path, new content) must read as
// changed until HAProxy loads it; an unchanged set must not.
func TestCertsChangedSinceLoad(t *testing.T) {
	state := t.TempDir()
	e := &Engine{StateDir: state}
	_, _, crtList := haproxy.Paths(state)
	bundle := filepath.Join(state, "certs", "c1", "bundle.pem")
	writeFile(t, bundle, "old cert")
	writeFile(t, crtList, bundle+" alpn h2,http/1.1\n")

	if changed, err := e.certsChangedSinceLoad(); err != nil || !changed {
		t.Fatalf("no record yet must read as changed: %v %v", changed, err)
	}
	e.saveLoadedCerts(e.certsBeforeLoad())
	if changed, err := e.certsChangedSinceLoad(); err != nil || changed {
		t.Fatalf("just recorded must read as unchanged: %v %v", changed, err)
	}

	writeFile(t, bundle, "renewed cert") // same path, new PEM
	if changed, _ := e.certsChangedSinceLoad(); !changed {
		t.Fatal("renewed certificate not noticed")
	}
	e.saveLoadedCerts(e.certsBeforeLoad())

	other := filepath.Join(state, "certs", "c2", "bundle.pem")
	writeFile(t, other, "second cert")
	writeFile(t, crtList, bundle+" alpn h2,http/1.1\n"+other+" alpn h2,http/1.1\n")
	if changed, _ := e.certsChangedSinceLoad(); !changed {
		t.Fatal("added certificate not noticed")
	}

	writeFile(t, loadedCertsPath(state), "{not json")
	if changed, _ := e.certsChangedSinceLoad(); !changed {
		t.Fatal("unreadable record must read as changed")
	}
}

// An unknown pre-reload state removes the record rather than keep a stale one.
func TestSaveLoadedCertsNilRemovesRecord(t *testing.T) {
	state := t.TempDir()
	e := &Engine{StateDir: state}
	_, _, crtList := haproxy.Paths(state)
	writeFile(t, crtList, "")
	e.saveLoadedCerts(e.certsBeforeLoad())
	if _, err := os.Stat(loadedCertsPath(state)); err != nil {
		t.Fatalf("record not written: %v", err)
	}
	e.saveLoadedCerts(nil)
	if _, err := os.Stat(loadedCertsPath(state)); !os.IsNotExist(err) {
		t.Fatalf("stale record kept: %v", err)
	}
}
