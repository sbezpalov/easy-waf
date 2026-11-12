// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hostd

import "os"

func setSocketPermissions(path string) error {
	return os.Chmod(path, 0o660)
}
