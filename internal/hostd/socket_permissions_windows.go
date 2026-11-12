// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hostd

// Windows AF_UNIX sockets do not expose POSIX permission bits. The appliance
// ships only on Linux, where socket_permissions_other.go enforces mode 0660.
func setSocketPermissions(string) error {
	return nil
}
