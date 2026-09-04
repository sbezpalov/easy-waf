// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package pemutil

import (
	"fmt"
	"os"
)

// WriteBundle writes fullchain + private key into one PEM for HAProxy.
func WriteBundle(dest, fullchainPath, keyPath string, mode os.FileMode) error {
	chain, err := os.ReadFile(fullchainPath)
	if err != nil {
		return fmt.Errorf("read fullchain: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, append(chain, key...), mode); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
