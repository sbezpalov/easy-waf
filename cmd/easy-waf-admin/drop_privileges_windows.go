// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "fmt"

// dropToStateOwner fails closed on Windows. The admin binary manages a Linux
// appliance and changing to a directory owner's numeric UID/GID has no Windows
// equivalent.
func dropToStateOwner(string) error {
	return fmt.Errorf("dropping privileges to the state directory owner is unsupported on Windows")
}
