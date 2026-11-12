// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"io"
	"os"
	"path/filepath"
)

// The apt action log lives in the root-only hostd state directory. These
// wrappers keep access descriptor-anchored there and fall back to plain file
// access only for the temp-directory override tests use. See statefile.go.

const maxAptActionLogBytes = 64 << 20

func underStateDir(path string) bool {
	_, err := stateRel(path)
	return err == nil
}

func createAptActionLog(path string) (*os.File, error) {
	if underStateDir(path) {
		return stateCreateFile(path, 0o640)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return os.Create(path)
}

func openAptActionLog(path string) (*os.File, error) {
	if underStateDir(path) {
		return stateOpenFile(path)
	}
	return os.Open(path)
}

func readAptActionLog(path string) ([]byte, error) {
	f, err := openAptActionLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxAptActionLogBytes))
}
