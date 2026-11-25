// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"fmt"
	"io"
	"os"
)

// MaxManagedConfigBytes is the largest Netplan or nftables rollback baseline.
const MaxManagedConfigBytes = 16 << 20

// ReadManagedConfig reads a complete regular file for the management panel.
func ReadManagedConfig(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("managed configuration is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, current) {
		return "", fmt.Errorf("managed configuration changed while opening")
	}
	if current.Size() > MaxManagedConfigBytes {
		return "", fmt.Errorf("managed configuration exceeds %d bytes", MaxManagedConfigBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxManagedConfigBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > MaxManagedConfigBytes {
		return "", fmt.Errorf("managed configuration exceeds %d bytes", MaxManagedConfigBytes)
	}
	return string(data), nil
}
