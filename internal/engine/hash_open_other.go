// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package engine

import "os"

func openArtifactForHash(path string) (*os.File, error) {
	return os.Open(path)
}
