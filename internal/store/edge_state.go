// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// EdgeApplyRecord is durable bookkeeping for one edge operation. A successful
// record advances AppliedGeneration. Failed records preserve the last proven
// generation; unknown and rollback records deliberately clear it.
type EdgeApplyRecord struct {
	Outcome           string
	At                time.Time
	AppliedGeneration *int64
	RevisionSHA       string
	ErrorCode         string
}

// GetEdgeStatus returns durable generation/apply state. Runtime is filled by
// the API because it observes the managed artifact on the local filesystem.
func (s *Store) GetEdgeStatus(ctx context.Context) (config.EdgeStatus, error) {
	var out config.EdgeStatus
	var applied sql.NullInt64
	var outcome, revisionSHA, errorCode sql.NullString
	var at sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT saved_generation, applied_generation, last_apply_outcome,
		       last_apply_at, last_apply_revision_sha, last_apply_error_code
		FROM edge_state WHERE singleton = 1`).Scan(
		&out.SavedGeneration, &applied, &outcome, &at, &revisionSHA, &errorCode,
	)
	if err != nil {
		return out, err
	}
	if applied.Valid {
		generation := applied.Int64
		out.AppliedGeneration = &generation
		pending := out.SavedGeneration != generation
		out.Pending = &pending
	}
	if outcome.Valid && at.Valid {
		out.LastApply = &config.EdgeLastApply{
			Outcome:     outcome.String,
			At:          at.Time.UTC(),
			RevisionSHA: revisionSHA.String,
			ErrorCode:   errorCode.String,
		}
	}
	return out, nil
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func normalizeEdgeApplyRecord(record EdgeApplyRecord) (EdgeApplyRecord, error) {
	if record.At.IsZero() {
		record.At = time.Now().UTC()
	} else {
		record.At = record.At.UTC()
	}
	switch record.Outcome {
	case config.EdgeApplyOutcomeSuccess:
		if record.AppliedGeneration == nil || *record.AppliedGeneration < 1 || record.ErrorCode != "" {
			return record, fmt.Errorf("invalid successful edge apply record")
		}
	case config.EdgeApplyOutcomeFailed:
		if record.AppliedGeneration != nil || record.RevisionSHA != "" || record.ErrorCode == "" {
			return record, fmt.Errorf("invalid failed edge apply record")
		}
	case config.EdgeApplyOutcomeUnknown:
		if record.AppliedGeneration != nil || record.ErrorCode == "" {
			return record, fmt.Errorf("invalid unknown edge apply record")
		}
	case config.EdgeApplyOutcomeRollback:
		if record.AppliedGeneration != nil || record.RevisionSHA == "" || record.ErrorCode != "" {
			return record, fmt.Errorf("invalid rollback edge apply record")
		}
	default:
		return record, fmt.Errorf("invalid edge apply outcome %q", record.Outcome)
	}
	return record, nil
}

func recordEdgeApply(ctx context.Context, exec contextExecer, record EdgeApplyRecord) error {
	record, err := normalizeEdgeApplyRecord(record)
	if err != nil {
		return err
	}
	var res sql.Result
	switch record.Outcome {
	case config.EdgeApplyOutcomeSuccess:
		res, err = exec.ExecContext(ctx, `
			UPDATE edge_state
			SET applied_generation = $1, last_apply_outcome = $2, last_apply_at = $3,
			    last_apply_revision_sha = $4, last_apply_error_code = NULL
			WHERE singleton = 1 AND saved_generation >= $1`,
			*record.AppliedGeneration, record.Outcome, record.At, nullStrPtr(record.RevisionSHA))
	case config.EdgeApplyOutcomeFailed:
		res, err = exec.ExecContext(ctx, `
			UPDATE edge_state
			SET last_apply_outcome = $1, last_apply_at = $2,
			    last_apply_revision_sha = NULL, last_apply_error_code = $3
			WHERE singleton = 1`, record.Outcome, record.At, record.ErrorCode)
	case config.EdgeApplyOutcomeUnknown:
		res, err = exec.ExecContext(ctx, `
			UPDATE edge_state
			SET applied_generation = NULL, last_apply_outcome = $1, last_apply_at = $2,
			    last_apply_revision_sha = $3, last_apply_error_code = $4
			WHERE singleton = 1`, record.Outcome, record.At, nullStrPtr(record.RevisionSHA), record.ErrorCode)
	case config.EdgeApplyOutcomeRollback:
		res, err = exec.ExecContext(ctx, `
			UPDATE edge_state
			SET applied_generation = NULL, last_apply_outcome = $1, last_apply_at = $2,
			    last_apply_revision_sha = $3, last_apply_error_code = NULL
			WHERE singleton = 1`, record.Outcome, record.At, record.RevisionSHA)
	}
	if err != nil {
		return err
	}
	if n, rowsErr := res.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if n != 1 {
		return fmt.Errorf("edge state row missing or generation invalid")
	}
	return nil
}

// RecordEdgeApply records an outcome that has no config revision transaction,
// such as a failed attempt or an unchanged startup reconcile.
func (s *Store) RecordEdgeApply(ctx context.Context, record EdgeApplyRecord) error {
	return recordEdgeApply(ctx, s.db, record)
}

// BumpEdgeGeneration records an edge-affecting artifact change that is not a
// table mutation covered by migration triggers (currently an explicit IPBL
// map sync). It returns the new generation.
func (s *Store) BumpEdgeGeneration(ctx context.Context) (int64, error) {
	var generation int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE edge_state SET saved_generation = saved_generation + 1
		WHERE singleton = 1 RETURNING saved_generation`).Scan(&generation)
	return generation, err
}
