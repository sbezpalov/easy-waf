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
	data, err := ReadManagedConfigBytes(path)
	return string(data), err
}

// ReadManagedConfigBytes returns a complete, size-checked file for redaction.
func ReadManagedConfigBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("managed configuration is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, current) {
		return nil, fmt.Errorf("managed configuration changed while opening")
	}
	if current.Size() > MaxManagedConfigBytes {
		return nil, fmt.Errorf("managed configuration exceeds %d bytes", MaxManagedConfigBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxManagedConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxManagedConfigBytes {
		return nil, fmt.Errorf("managed configuration exceeds %d bytes", MaxManagedConfigBytes)
	}
	return data, nil
}
