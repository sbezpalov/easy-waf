// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func allowRootPeer(conn *net.UnixConn) error {
	if peerCheckBypassed() {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if cred.Uid != 0 {
		return fmt.Errorf("APT peer uid %d is not root", cred.Uid)
	}
	return nil
}

func validateAPTWorkerDirectory(path string) error {
	fd, err := stateRootFD(path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return validateAPTPrivateDirectoryFD(fd)
}

func validateAPTPrivateDirectoryFD(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&0o077 != 0 {
		return errors.New("APT worker directory must be root-owned and private")
	}
	return nil
}

// The internal flock lease is separate from dpkg's POSIX locks. Both the worker
// and maintenance helper take it before touching the actual package locks.
func acquireAPTExecutionLease(ctx context.Context, wait bool) (func() error, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("APT execution lease requires root")
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	dirFD, err := stateRootFD(stateDir)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	if err := validateAPTPrivateDirectoryFD(dirFD); err != nil {
		return nil, err
	}
	const name = "apt-execution.lock"
	fd, err := openatBeneath(dirFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(stateDir, name))
	failed := true
	defer func() {
		if failed {
			_ = f.Close()
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o077 != 0 || st.Nlink != 1 {
		return nil, errors.New("unsafe APT execution lease file")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !wait || (!errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR)) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	var current unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if current.Dev != st.Dev || current.Ino != st.Ino || current.Nlink != 1 || current.Uid != 0 || current.Mode&0o077 != 0 {
		return nil, errors.New("APT execution lease changed while waiting")
	}
	if err := validateAPTPrivateDirectoryFD(dirFD); err != nil {
		return nil, err
	}
	failed = false
	return f.Close, nil
}
