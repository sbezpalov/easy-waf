// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"path/filepath"
)

func rollbackRevertingPath(kind, token string) string {
	return filepath.Join(stateDir, "rollback", kind+"-"+token+".reverting")
}

// claimRollbackBackup makes recovery non-confirmable before touching live state.
// Renaming the backup preserves both the original bytes and the recovery phase
// across failures/restarts without a second, independently updated marker file.
// The caller holds the rollback operation lock.
func claimRollbackBackup(kind, token string) (string, []byte, bool, error) {
	pending, reverting := rollbackBackupPath(kind, token), rollbackRevertingPath(kind, token)
	_, pendingExists, err := stateFileSize(pending)
	if err != nil {
		return "", nil, false, err
	}
	_, revertingExists, err := stateFileSize(reverting)
	if err != nil {
		return "", nil, false, err
	}
	if pendingExists && revertingExists {
		return "", nil, false, fmt.Errorf("conflicting pending and reverting backups; recovery requires operator inspection")
	}
	if !pendingExists && !revertingExists {
		return "", nil, false, nil
	}
	if err := invalidateRollbackReceipt(kind); err != nil {
		return "", nil, false, err
	}
	if pendingExists {
		if err := stateRenameFile(pending, reverting); err != nil {
			return "", nil, false, fmt.Errorf("mark rollback as started: %w", err)
		}
	}
	data, exists, err := readRollbackBackup(reverting)
	if err != nil {
		return "", nil, false, err
	}
	if !exists {
		return "", nil, false, fmt.Errorf("rollback backup disappeared after recovery started")
	}
	return reverting, data, true, nil
}
