// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Validate runs `haproxy -c -f path` using haproxyBinary.
func Validate(haproxyBinary, cfgPath string) error {
	cmd := exec.Command(haproxyBinary, "-c", "-f", cfgPath)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("haproxy -c: %w", err)
	}
	return nil
}

// WriteAtomic writes data to path via a temp file in the same directory, then renames.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReloadHAProxy reloads HAProxy if it is already running, otherwise starts it.
// Plain `systemctl reload` fails with "cannot reload" when the unit is inactive,
// which breaks apply-edge / API Apply on a cold edge after a template upgrade.
func ReloadHAProxy() error {
	cmd := exec.Command("systemctl", "reload-or-restart", "haproxy")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl reload-or-restart haproxy: %w", err)
	}
	return nil
}
