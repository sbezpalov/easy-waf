// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package disk

import "golang.org/x/sys/unix"

func statfsMount(path string) (Mount, fsID, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Mount{}, fsID{}, err
	}
	bsize := uint64(st.Bsize) //nolint:gosec // block size reported by the kernel is never negative
	total := uint64(st.Blocks) * bsize
	free := uint64(st.Bavail) * bsize
	var used uint64
	if total > free {
		used = total - free
	}
	pct := 0
	if total > 0 {
		pct = int((used * 100) / total) //nolint:gosec
		if pct > 100 {
			pct = 100
		}
	}
	id := fsID{val0: st.Fsid.Val[0], val1: st.Fsid.Val[1]}
	return Mount{
		Path:        path,
		TotalBytes:  total,
		FreeBytes:   free,
		UsedBytes:   used,
		UsedPercent: pct,
	}, id, nil
}
