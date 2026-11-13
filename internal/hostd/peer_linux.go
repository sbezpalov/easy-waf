// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// The service account is a Linux appliance identity. Failure to resolve it
// leaves non-root peers denied; development builds do not perform this lookup.
var easyWafUID = -1

func init() {
	if u, err := user.Lookup("easy-waf"); err == nil {
		easyWafUID, _ = strconv.Atoi(u.Uid)
	}
}

var trustedAPIPeerExecutables = []string{
	"/usr/sbin/easy-waf-api",
	"/usr/sbin/easy-wafd",
}

func allowPeer(conn *net.UnixConn) error {
	if peerCheckBypassed() {
		return nil
	}
	raw, err := conn.File()
	if err != nil {
		return err
	}
	defer raw.Close()
	fd := int(raw.Fd())
	ucred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return err
	}
	uid := int(ucred.Uid)
	// Root may call the broker (emergency tooling). Non-root peers must be the
	// easy-waf service account *and* the management API binary — acmed shares
	// that uid but parses internet ACME/DNS responses and must not inherit the
	// full hostd allowlist (reboot, apt, netplan/nft, useradd, stop postgresql).
	if uid == 0 {
		return nil
	}
	if easyWafUID < 0 || uid != easyWafUID {
		return fmt.Errorf("uid %d", uid)
	}
	if err := requireAPIPeerExe(int(ucred.Pid)); err != nil {
		return err
	}
	return nil
}

// requireAPIPeerExe allows only the root-owned installed API binary (or the
// legacy installed alias) for the easy-waf uid. Comparing the executable inode
// with the trusted host path prevents a same-uid process from impersonating the
// API with an attacker-writable file that merely has the same basename.
func requireAPIPeerExe(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("peer pid")
	}
	procExe := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err := os.Readlink(procExe)
	if err != nil {
		return fmt.Errorf("peer exe: %w", err)
	}
	for _, trustedPath := range trustedAPIPeerExecutables {
		if exe != trustedPath {
			continue
		}
		peerInfo, err := os.Stat(procExe)
		if err != nil {
			return fmt.Errorf("peer exe stat: %w", err)
		}
		trustedInfo, err := os.Stat(trustedPath)
		if err != nil {
			return fmt.Errorf("trusted peer exe stat: %w", err)
		}
		stat, ok := trustedInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !trustedInfo.Mode().IsRegular() || trustedInfo.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("trusted peer exe %q has unsafe ownership or mode", trustedPath)
		}
		if !os.SameFile(peerInfo, trustedInfo) {
			return fmt.Errorf("peer exe %q does not match installed binary", exe)
		}
		return nil
	}
	return fmt.Errorf("peer exe %q not allowed", exe)
}
