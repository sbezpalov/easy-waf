// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

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

// requireAPIPeerExe allows only easy-waf-api (and the legacy easy-wafd alias)
// for the easy-waf uid. Fail closed when /proc/<pid>/exe cannot be resolved.
func requireAPIPeerExe(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("peer pid")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("peer exe: %w", err)
	}
	// Kernel may append " (deleted)" when the binary was replaced underfoot.
	exe = strings.TrimSuffix(exe, " (deleted)")
	base := filepath.Base(exe)
	switch base {
	case "easy-waf-api", "easy-wafd":
		return nil
	default:
		return fmt.Errorf("peer exe %q not allowed", base)
	}
}
