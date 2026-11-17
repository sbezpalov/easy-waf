// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package generator assembles the embedded web UI from an explicit manifest.
package generator

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

var defaultManifest = []string{
	"document-before-tokens.html",
	"styles/tokens.css",
	"styles/application.css",
	"document-before-screens.html",
	"screens/dashboard.html",
	"screens/applications.html",
	"screens/certificates.html",
	"screens/security.html",
	"screens/crowdsec.html",
	"screens/fail2ban.html",
	"document-after-fail2ban.html",
}

// DefaultManifest returns the ordered source files used for the web UI bundle.
func DefaultManifest() []string {
	return append([]string(nil), defaultManifest...)
}

// Build concatenates manifest entries after validating that the source tree
// contains exactly those files. Newlines are normalized so Windows and macOS
// checkouts produce the same committed bundle.
func Build(source fs.FS, manifest []string) ([]byte, error) {
	if len(manifest) == 0 {
		return nil, fmt.Errorf("webui generator: manifest is empty")
	}

	wanted := make(map[string]struct{}, len(manifest))
	for _, name := range manifest {
		if !fs.ValidPath(name) || name == "." || path.Clean(name) != name {
			return nil, fmt.Errorf("webui generator: invalid manifest path %q", name)
		}
		if _, exists := wanted[name]; exists {
			return nil, fmt.Errorf("webui generator: duplicate manifest path %q", name)
		}
		wanted[name] = struct{}{}
	}

	var files []string
	if err := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("webui generator: source %q is not a regular file", name)
		}
		files = append(files, name)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("webui generator: inventory source tree: %w", err)
	}
	sort.Strings(files)
	for _, name := range files {
		if _, ok := wanted[name]; !ok {
			return nil, fmt.Errorf("webui generator: unexpected source file %q", name)
		}
	}

	var output bytes.Buffer
	for _, name := range manifest {
		data, err := fs.ReadFile(source, name)
		if err != nil {
			return nil, fmt.Errorf("webui generator: read %q: %w", name, err)
		}
		output.Write(normalizeNewlines(data))
	}
	return output.Bytes(), nil
}

// WriteDefault writes the default bundle only when its bytes changed.
func WriteDefault(sourceDir, outputPath string) error {
	data, err := Build(os.DirFS(sourceDir), DefaultManifest())
	if err != nil {
		return err
	}
	current, err := os.ReadFile(outputPath)
	if err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("webui generator: read output: %w", err)
	}
	// The generated bundle is a public embedded asset, not secret material.
	//nolint:gosec // Keep normal source-tree permissions for the committed file.
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("webui generator: write output: %w", err)
	}
	return nil
}

func normalizeNewlines(data []byte) []byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return []byte(text)
}
