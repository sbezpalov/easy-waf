// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

const revisionPreviewBytes = 8 << 10

// RevisionPreview reads a bounded prefix of a generated revision preview.
// It returns no data for missing previews, links or special files.
func (e *Engine) RevisionPreview(sha256Full string) (prefix []byte, truncated bool) {
	var sum [sha256.Size]byte
	if len(sha256Full) != hex.EncodedLen(len(sum)) {
		return nil, false
	}
	if _, err := hex.Decode(sum[:], []byte(sha256Full)); err != nil {
		return nil, false
	}
	root, err := os.OpenRoot(e.StateDir)
	if err != nil {
		return nil, false
	}
	defer root.Close()
	revisions, err := root.OpenRoot("revisions")
	if err != nil {
		return nil, false
	}
	defer revisions.Close()
	path := "haproxy-" + sha256Full[:12] + ".cfg"
	info, err := revisions.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	f, err := revisions.OpenFile(path, os.O_RDONLY|artifactReadFlags, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, revisionPreviewBytes+1))
	if err != nil {
		return nil, false
	}
	if len(data) > revisionPreviewBytes {
		return data[:revisionPreviewBytes], true
	}
	return data, false
}
