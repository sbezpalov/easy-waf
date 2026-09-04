// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package disk

import "fmt"

// Mount is filesystem usage for one path (statfs).
type Mount struct {
	Path        string `json:"path"`
	TotalBytes  uint64 `json:"total_bytes"`
	FreeBytes   uint64 `json:"free_bytes"`
	UsedBytes   uint64 `json:"used_bytes"`
	UsedPercent int    `json:"used_percent"`
}

type fsID struct {
	val0 int32
	val1 int32
}

// Usage returns statfs-based usage for the given paths (skips paths that fail).
// Duplicate filesystems (same device) are included once (first successful path wins).
func Usage(paths ...string) ([]Mount, error) {
	if len(paths) == 0 {
		paths = []string{"/", "/var"}
	}
	seen := make(map[fsID]struct{})
	out := make([]Mount, 0, len(paths))
	for _, path := range paths {
		m, id, err := statfsMount(path)
		if err != nil {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("disk: no mount stats available")
	}
	return out, nil
}
