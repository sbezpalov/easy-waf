// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package rollback

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// PendingChanges reads the broker's root-owned rollback state. It never
// returns the bearer token required to commit a change.
func PendingChanges(ctx context.Context) (hostspec.RollbackStatus, error) {
	out, err := runner.Privileged(ctx, "rollback-status")
	if err != nil {
		return hostspec.RollbackStatus{}, err
	}
	var status hostspec.RollbackStatus
	if err := json.Unmarshal(out, &status); err != nil {
		return hostspec.RollbackStatus{}, fmt.Errorf("decode rollback status: %w", err)
	}
	if status.Changes == nil || len(status.Changes) > 2 {
		return hostspec.RollbackStatus{}, fmt.Errorf("invalid rollback status")
	}
	seen := make(map[string]bool, len(status.Changes))
	for _, change := range status.Changes {
		if (change.Kind != "nft" && change.Kind != "netplan") ||
			(change.Phase != "pending" && change.Phase != "expired" && change.Phase != "reverting") ||
			!hostspec.ValidToken(change.OperationID) || seen[change.Kind] {
			return hostspec.RollbackStatus{}, fmt.Errorf("invalid rollback status")
		}
		if change.Confirmable != (change.Phase == "pending") {
			return hostspec.RollbackStatus{}, fmt.Errorf("invalid rollback status")
		}
		if change.ExpiresAt != nil && change.ExpiresAt.IsZero() {
			return hostspec.RollbackStatus{}, fmt.Errorf("invalid rollback status")
		}
		seen[change.Kind] = true
	}
	return status, nil
}
