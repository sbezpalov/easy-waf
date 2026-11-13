// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func acquireDpkgLocks(ctx context.Context) (func() error, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("post-upgrade broker restart requires root")
	}
	return acquirePackageLocks(ctx, "/var/lib/dpkg", 0)
}

// Private path/owner parameters let tests use owned temporary files, never the
// workstation's package database. The public CLI accepts no path or command.
func acquirePackageLocks(ctx context.Context, directory string, owner uint32) (_ func() error, err error) {
	dirFD, err := stateRootFD(directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	var dirStat unix.Stat_t
	if err := unix.Fstat(dirFD, &dirStat); err != nil {
		return nil, err
	}
	if dirStat.Uid != owner || dirStat.Mode&0o022 != 0 {
		return nil, errors.New("unsafe package lock directory ownership or permissions")
	}
	names := []string{"lock-frontend", "lock"} // same order as APT before invoking dpkg
	files := make([]int, 0, len(names))
	stats := make([]unix.Stat_t, 0, len(names))
	release := func() error {
		var result error
		for i := len(files) - 1; i >= 0; i-- {
			result = errors.Join(result, unix.Close(files[i]))
		}
		return result
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, release())
		}
	}()
	for _, name := range names {
		// Never create, unlink or truncate dpkg's lock files. A new inode would
		// cease coordinating with an existing package manager. NONBLOCK avoids
		// blocking on a substituted special file before its type is verified.
		fd, openErr := openatBeneath(dirFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if openErr != nil {
			return nil, fmt.Errorf("open %s: %w", name, openErr)
		}
		files = append(files, fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != owner || st.Mode&0o022 != 0 || st.Nlink != 1 {
			return nil, fmt.Errorf("unsafe package lock file %s", name)
		}
		stats = append(stats, st)
	}
	for _, fd := range files {
		if err := waitPackageLock(ctx, fd); err != nil {
			return nil, err
		}
	}
	// A removed/replaced inode while waiting cannot authorize a restart.
	for i, name := range names {
		var current unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if current.Dev != stats[i].Dev || current.Ino != stats[i].Ino || current.Uid != owner || current.Mode&0o022 != 0 || current.Nlink != 1 {
			return nil, fmt.Errorf("package lock %s changed while waiting", name)
		}
	}
	return release, nil
}

func waitPackageLock(ctx context.Context, fd int) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(unix.SEEK_SET)}
		err := unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("lock package database: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
