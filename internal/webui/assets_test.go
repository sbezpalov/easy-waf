// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedFavicon(t *testing.T) {
	assets, err := fs.Sub(Assets, "dist")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	http.FileServer(http.FS(assets)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("favicon status %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "image/") {
		t.Fatalf("favicon content type %q", got)
	}
	data := w.Body.Bytes()
	if len(data) < 6 || binary.LittleEndian.Uint16(data) != 0 || binary.LittleEndian.Uint16(data[2:]) != 1 {
		t.Fatal("favicon is not an ICO image")
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	if count == 0 || len(data) < 6+16*count {
		t.Fatal("invalid icon directory")
	}
	for i := range count {
		entry := data[6+16*i : 6+16*(i+1)]
		size, offset := uint64(binary.LittleEndian.Uint32(entry[8:])), uint64(binary.LittleEndian.Uint32(entry[12:]))
		if size == 0 || offset < uint64(6+16*count) || offset+size > uint64(len(data)) {
			t.Fatal("invalid icon image bounds")
		}
		image, err := png.Decode(bytes.NewReader(data[offset : offset+size]))
		if err != nil {
			t.Fatalf("decode icon image: %v", err)
		}
		width, height := int(entry[0]), int(entry[1])
		if width == 0 {
			width = 256
		}
		if height == 0 {
			height = 256
		}
		if image.Bounds().Dx() != width || image.Bounds().Dy() != height {
			t.Fatal("decoded icon dimensions differ from its directory entry")
		}
	}
}
