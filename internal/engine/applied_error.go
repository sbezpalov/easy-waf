// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

// AppliedError reports a failure after the configuration was applied and kept
// in place. Callers must not compensate by undoing the saved configuration.
type AppliedError struct {
	Err error
}

func (e *AppliedError) Error() string {
	return "configuration applied, but a later step failed: " + e.Err.Error()
}

// Unwrap preserves the cause, including a deadline or database failure.
func (e *AppliedError) Unwrap() error { return e.Err }

func appliedOperationError(applied bool, err error) error {
	if applied && err != nil {
		return &AppliedError{Err: err}
	}
	return err
}
