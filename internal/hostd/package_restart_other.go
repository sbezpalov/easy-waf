// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import (
	"context"
	"errors"
)

func acquireDpkgLocks(context.Context) (func() error, error) {
	return nil, errors.New("post-upgrade broker restart is supported only on Linux")
}
