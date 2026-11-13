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
	"github.com/easy-waf/easy-waf/internal/engine"
)

// applyOrUndo applies the edge after a database change and, when the apply
// is rejected, reverts that change with undo. A failure after the new edge
// configuration is already applied keeps the saved change.
//
// Handlers used to commit the row and then apply. A row HAProxy rejected
// stayed in the database ("saved but edge apply failed"), and every later
// apply rendered it again and failed too, ACME renewals included, until
// someone found and fixed it. Undo a rejected change to keep the database
// aligned with the edge; AppliedError instead means the new configuration
// is already live and its saved state must remain in place.
func (s *Server) applyOrUndo(ctx context.Context, label string, undo func(context.Context) error) error {
	release, lerr := s.Eng.Store.AcquireAdvisoryLock(ctx, engine.ApplyOrUndoAdvisoryLockKey)
	if lerr != nil {
		return lerr
	}
	defer func() { _ = release() }()
	err := s.maybeAutoApply(ctx, label)
	return undoRejectedApply(ctx, err, undo)
}

func undoRejectedApply(ctx context.Context, err error, undo func(context.Context) error) error {
	if err == nil {
		return nil
	}
	var applied *engine.AppliedError
	if errors.As(err, &applied) {
		return err
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

// applyTimeout bounds the normal work of an apply started by a request,
// including the lock wait. Recovery after a failed reload has its own budget.
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
// otherwise 422 — the stored configuration could not be put live. An already
// applied configuration with a later failure reports 500 and its kept state.
// HAProxy -c / filesystem detail stays in the process log, not the response.
func writeApplyRejected(w http.ResponseWriter, err error) {
	var applied *engine.AppliedError
	if errors.As(err, &applied) {
		writeClientError(w, http.StatusInternalServerError, "configuration applied; check status before retrying", err)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeClientError(w, http.StatusServiceUnavailable, "apply timed out; retry", err)
		return
	}
	writeClientError(w, http.StatusUnprocessableEntity, "apply failed", err)
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
