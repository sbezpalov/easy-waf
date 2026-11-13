// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package staging manages short-lived inputs handed to the privileged broker.
package staging

import (
	"errors"
	"fmt"
	"os"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// WithFile writes a unique 0600 file, closes it before consume, and removes it
// after consume returns on either success or failure. The broker materializes
// its own root-owned copy synchronously, so the client need not retain inputs.
func WithFile(pattern string, data []byte, consume func(string) error) error {
	return withFile(hostspec.StagingDirPrefix, pattern, data, consume)
}

func withFile(dir, pattern string, data []byte, consume func(string) error) (err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close() // also covers a failed write/close before consume
		if removeErr := os.Remove(f.Name()); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove staged file: %w", removeErr))
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return consume(f.Name())
}
