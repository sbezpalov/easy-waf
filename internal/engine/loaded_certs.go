// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/haproxy"
)

// Certificates are not managed artifacts: snapshots would copy private keys
// into every revision, and a rollback would bring back replaced (possibly
// compromised) keys. But ApplyIfChanged must still notice a certificate
// renewed in place under the same ID, whose new PEM HAProxy has not loaded.
// Comparing with the pre-render snapshot cannot tell: a failed apply rolls
// back the config but leaves the new PEM on disk, so the next render looks
// unchanged while HAProxy still serves the old certificate.
//
// So the engine records, whenever HAProxy (re)loads, the SHA-256 of every
// certificate file the crt-list names — hashes only, no key material — and
// ApplyIfChanged compares the files the new crt-list names against that
// record.

type loadedCerts struct {
	// Files maps each certificate path in the crt-list to its SHA-256 ("" when
	// the file was missing).
	Files map[string]string `json:"files"`
}

func loadedCertsPath(stateDir string) string {
	return filepath.Join(stateDir, "haproxy", ".loaded-certs.json")
}

// crtListCertPaths returns the certificate paths a crt-list names (the first
// field of every non-comment line). A missing crt-list names none.
func crtListCertPaths(crtListPath string) ([]string, error) {
	data, err := os.ReadFile(crtListPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths = append(paths, strings.Fields(line)[0])
	}
	return paths, sc.Err()
}

// currentCertHashes hashes the certificate files the on-disk crt-list names.
func (e *Engine) currentCertHashes() (map[string]string, error) {
	_, _, crtListPath := haproxy.Paths(e.StateDir)
	paths, err := crtListCertPaths(crtListPath)
	if err != nil {
		return nil, fmt.Errorf("read crt-list: %w", err)
	}
	files := make(map[string]string, len(paths))
	for _, p := range paths {
		sum, err := sha256HexFile(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			files[p] = ""
		case err != nil:
			return nil, fmt.Errorf("hash certificate %s: %w", p, err)
		default:
			files[p] = sum
		}
	}
	return files, nil
}

// certsBeforeLoad hashes the certificate files HAProxy is about to load. It
// is taken before the reload, so a file rewritten in between (a PEM managed
// outside easy-waf) is recorded with its old hash and costs one extra apply,
// instead of being recorded as loaded when HAProxy never saw it. A nil result
// means "unknown": saveLoadedCerts then removes the record.
func (e *Engine) certsBeforeLoad() map[string]string {
	files, err := e.currentCertHashes()
	if err != nil {
		log.Printf("engine: hash certificates before reload (next reconcile will re-apply): %v", err)
		return nil
	}
	return files
}

// saveLoadedCerts records files (from certsBeforeLoad) as what HAProxy has
// just loaded (or, with reloads skipped, will load when the caller reloads,
// the same assumption the engine makes for the config). A failure only costs
// one extra apply later — a missing record reads as "changed" — so it is
// logged rather than failing an apply that already succeeded.
func (e *Engine) saveLoadedCerts(files map[string]string) {
	path := loadedCertsPath(e.StateDir)
	var err error
	if files == nil {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else {
		var body []byte
		body, err = json.MarshalIndent(loadedCerts{Files: files}, "", "  ")
		if err == nil {
			err = apply.WriteAtomic(path, append(body, '\n'), 0o640)
		}
	}
	if err != nil {
		log.Printf("engine: record loaded certificates (next reconcile will re-apply): %v", err)
	}
}

// certsChangedSinceLoad reports whether the certificate files the on-disk
// crt-list names differ from those HAProxy last loaded. Without a record
// (first start after an upgrade, or a lost or unreadable file) it answers
// true: one extra apply is harmless, a certificate left unloaded is not.
func (e *Engine) certsChangedSinceLoad() (bool, error) {
	data, err := os.ReadFile(loadedCertsPath(e.StateDir))
	if err != nil {
		// Missing, or unreadable (written by another account, say): re-apply
		// rather than fail the reconcile or trust nothing.
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("engine: read loaded certificates record (re-applying): %v", err)
		}
		return true, nil
	}
	var rec loadedCerts
	if err := json.Unmarshal(data, &rec); err != nil {
		return true, nil // unreadable record: re-apply rather than trust it
	}
	cur, err := e.currentCertHashes()
	if err != nil {
		return false, err
	}
	if len(cur) != len(rec.Files) {
		return true, nil
	}
	for p, sum := range cur {
		if was, ok := rec.Files[p]; !ok || was != sum {
			return true, nil
		}
	}
	return false, nil
}
