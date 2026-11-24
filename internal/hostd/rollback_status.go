// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

const maxRollbackDeadlineBytes = 1024

type rollbackDeadlineRecord struct {
	ExpiresAt time.Time `json:"expires_at"`
}

func rollbackDeadlinePath(kind, token string) string {
	return filepath.Join(stateDir, "rollback", kind+"-"+token+".deadline")
}

func writeRollbackDeadline(kind, token string, deadline time.Time) error {
	data, err := json.Marshal(rollbackDeadlineRecord{ExpiresAt: deadline.UTC()})
	if err != nil {
		return err
	}
	return stateWriteFile(rollbackDeadlinePath(kind, token), append(data, '\n'), 0o600)
}

func readRollbackDeadline(kind, token string) (*time.Time, error) {
	f, err := stateOpenFile(rollbackDeadlinePath(kind, token))
	if os.IsNotExist(err) {
		// Pending backups created by an older broker have no metadata. They
		// remain recoverable and confirmable under the legacy rules.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRollbackDeadlineBytes {
		return nil, fmt.Errorf("invalid rollback deadline record")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxRollbackDeadlineBytes+1))
	dec.DisallowUnknownFields()
	var record rollbackDeadlineRecord
	if err := dec.Decode(&record); err != nil || record.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("invalid rollback deadline record")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid rollback deadline record")
	}
	deadline := record.ExpiresAt.UTC()
	return &deadline, nil
}

func rollbackOperationID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func parseRollbackBackupName(name string) (kind, token, phase string, ok bool) {
	base, pending := strings.CutSuffix(name, ".bak")
	phase = "pending"
	if !pending {
		base, pending = strings.CutSuffix(name, ".reverting")
		phase = "reverting"
	}
	if !pending {
		return "", "", "", false
	}
	kind, token, ok = strings.Cut(base, "-")
	if !ok || (kind != "nft" && kind != "netplan") || !hostspec.ValidToken(token) {
		return "", "", "", false
	}
	return kind, token, phase, true
}

func pendingRollbackStatus(now time.Time) (hostspec.RollbackStatus, error) {
	status := hostspec.RollbackStatus{Changes: []hostspec.PendingRollback{}}
	dir, err := stateOpenFile(filepath.Join(stateDir, "rollback"))
	if os.IsNotExist(err) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return status, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		kind, token, phase, ok := parseRollbackBackupName(entry.Name())
		if !ok {
			continue
		}
		deadline, err := readRollbackDeadline(kind, token)
		if err != nil {
			return status, err
		}
		confirmable := phase == "pending"
		if confirmable && deadline != nil && !now.Before(*deadline) {
			phase = "expired"
			confirmable = false
		}
		status.Changes = append(status.Changes, hostspec.PendingRollback{
			OperationID: rollbackOperationID(token),
			Kind:        kind,
			Phase:       phase,
			ExpiresAt:   deadline,
			Confirmable: confirmable,
		})
	}
	sort.Slice(status.Changes, func(i, j int) bool {
		if status.Changes[i].Kind != status.Changes[j].Kind {
			return status.Changes[i].Kind < status.Changes[j].Kind
		}
		return status.Changes[i].OperationID < status.Changes[j].OperationID
	})
	return status, nil
}

func rollbackStatus(ctx context.Context) Response {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	retry := time.NewTicker(50 * time.Millisecond)
	defer retry.Stop()
	for {
		unlock, err := lockRollback(false)
		if err == nil {
			defer unlock()
			break
		}
		if !errors.Is(err, hostspec.ErrRollbackStatusBusy) {
			return failResp(err.Error(), 1)
		}
		select {
		case <-ctx.Done():
			return failResp(err.Error(), hostspec.RollbackStatusBusyCode)
		case <-retry.C:
		}
	}
	status, err := pendingRollbackStatus(time.Now().UTC())
	if err != nil {
		return failResp(err.Error(), 1)
	}
	data, err := json.Marshal(status)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	return okResp(data, nil, 0)
}
