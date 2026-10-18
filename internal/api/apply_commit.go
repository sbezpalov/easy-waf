// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// applyOrUndo applies the edge after a database change and, when the apply
// fails, reverts that change with undo.
//
// Handlers used to commit the row and then apply. A row HAProxy rejected
// stayed in the database ("saved but edge apply failed"), and every later
// apply rendered it again and failed too, ACME renewals included, until
// someone found and fixed it. A failed Apply has already put the previous
// artifact set back on disk, so undoing the row leaves the database and the
// edge matching again.
func (s *Server) applyOrUndo(ctx context.Context, label string, undo func(context.Context) error) error {
	err := s.maybeAutoApply(ctx, label)
	if err == nil {
		return nil
	}
	// The undo must survive a client that disconnected, but not hang: it
	// gets its own deadline rather than the (possibly spent) request one.
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), undoTimeout)
	defer cancel()
	if uerr := undo(uctx); uerr != nil {
		return fmt.Errorf("edge apply failed: %w; undoing the database change also failed, so it is saved but not live: %v", err, uerr)
	}
	return fmt.Errorf("change not saved, edge apply failed: %w", err)
}

// applyTimeout bounds an apply started by a request, the wait for the apply
// lock included.
const applyTimeout = 2 * time.Minute

// undoTimeout bounds the compensating database write after a failed apply.
const undoTimeout = 30 * time.Second

// applyContext detaches an apply from the request: a client that disconnects
// after HAProxy reloaded used to cancel the revision/audit write, and the
// failed bookkeeping then rolled the whole change back.
func applyContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), applyTimeout)
}

// writeApplyRejected reports a failed apply: 503 when it ran out of time
// (typically waiting for another apply to finish, so a retry can succeed),
// otherwise 422 — the stored configuration could not be put live.
func writeApplyRejected(w http.ResponseWriter, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	http.Error(w, err.Error(), http.StatusUnprocessableEntity)
}

// cloneApplication deep-copies a so later in-place edits cannot leak into the
// copy kept for undo.
func cloneApplication(a config.Application) (config.Application, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return config.Application{}, err
	}
	var out config.Application
	err = json.Unmarshal(b, &out)
	return out, err
}

// restoreApplication is the undo for an update: put the previous row back.
func (s *Server) restoreApplication(prev config.Application) func(context.Context) error {
	return func(ctx context.Context) error {
		return s.Eng.Store.UpsertApplication(ctx, &prev)
	}
}
