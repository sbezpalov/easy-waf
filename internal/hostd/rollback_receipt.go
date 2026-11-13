// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// One receipt per subsystem bounds storage and contains only a token, never
// the network/firewall backup. Starting another apply invalidates the receipt.
func rollbackReceiptPath(kind string) string {
	return filepath.Join(stateDir, "rollback", kind+".committed")
}

// A pending backup takes precedence over any stale receipt during recovery.
// Invalidate it before restoring the live configuration, so a recovered or
// inconsistent state directory cannot later claim the reverted change was kept.
func invalidateRollbackReceipt(kind string) error {
	if err := stateRemoveFile(rollbackReceiptPath(kind)); err != nil {
		return fmt.Errorf("invalidate rollback confirmation receipt: %w", err)
	}
	return nil
}

func readRollbackReceipt(kind string) (string, error) {
	f, err := stateOpenFile(rollbackReceiptPath(kind))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read rollback confirmation receipt: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("rollback confirmation receipt is not a regular file")
	}
	// Tokens are at most 64 bytes. Never load an unexpectedly large receipt or
	// accept a truncated prefix as evidence that a change was confirmed.
	data, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil {
		return "", err
	}
	if !hostspec.ValidToken(string(data)) {
		return "", fmt.Errorf("invalid rollback confirmation receipt")
	}
	return string(data), nil
}
