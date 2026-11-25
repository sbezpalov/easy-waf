// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestRevisionPreviewReadsOnlyRegularBoundedFiles(t *testing.T) {
	state := t.TempDir()
	e := New(state, nil, config.GlobalSettings{})
	revisions := filepath.Join(state, "revisions")
	if err := os.Mkdir(revisions, 0o750); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	name := "haproxy-" + sha[:12] + ".cfg"
	path := filepath.Join(revisions, name)
	writeArtifactTestFile(t, path, "global\n")
	if got, truncated := e.RevisionPreview(sha); string(got) != "global\n" || truncated {
		t.Fatalf("unexpected small preview: %q, truncated=%v", got, truncated)
	}
	content := strings.Repeat("a", revisionPreviewBytes) + "past the limit"
	writeArtifactTestFile(t, path, content)
	if got, truncated := e.RevisionPreview(sha); !bytes.Equal(got, []byte(content[:revisionPreviewBytes])) || !truncated {
		t.Fatalf("preview length=%d, truncated=%v", len(got), truncated)
	}
	for _, invalid := range []string{"", sha[:12], strings.Repeat("z", 64), strings.Repeat("b", 64)} {
		if got, truncated := e.RevisionPreview(invalid); got != nil || truncated {
			t.Fatal("an invalid or missing revision returned a preview")
		}
	}

	t.Run("outside state links", func(t *testing.T) {
		outside := t.TempDir()
		target := filepath.Join(outside, name)
		writeArtifactTestFile(t, target, "private fixture")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if got, _ := e.RevisionPreview(sha); got != nil {
			t.Fatal("preview followed a link to a file outside state")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(revisions); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, revisions); err != nil {
			t.Fatal(err)
		}
		if got, _ := e.RevisionPreview(sha); got != nil {
			t.Fatal("preview followed a directory link outside state")
		}
	})
}
