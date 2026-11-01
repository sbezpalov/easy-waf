// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// dropToStateOwner makes a root process continue as the account that owns
// stateDir, the identity the API writes under. Files written as root would stay
// root:root 0640, which the unprivileged HAProxy unit cannot read, so its reload
// fails and its next restart takes the edge down.
//
// Call it after reading root-only files such as easy-waf.env.
func dropToStateOwner(stateDir string) error {
	uid, gid, err := stateOwner(stateDir)
	if err != nil {
		return err
	}
	if !needsDrop(os.Geteuid(), uid) {
		return nil
	}
	groups, err := supplementaryGroups(uid, gid)
	if err != nil {
		return err
	}
	ids := identitySwitch{setgroups: syscall.Setgroups, setgid: syscall.Setgid, setuid: syscall.Setuid}
	if err := ids.apply(uid, gid, groups); err != nil {
		return fmt.Errorf("drop privileges to uid %d: %w", uid, err)
	}
	return nil
}

func stateOwner(stateDir string) (uid, gid int, err error) {
	info, err := os.Stat(stateDir)
	if err != nil {
		return 0, 0, fmt.Errorf("state directory: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("state directory %s: no owner information", stateDir)
	}
	return int(st.Uid), int(st.Gid), nil
}

// needsDrop is false for a root-owned state directory: there is no service
// account to become, and root-owned state is what such a host expects.
func needsDrop(euid, owner int) bool {
	return euid == 0 && owner != 0
}

// supplementaryGroups keeps the account's memberships: easy-waf reaches the
// HAProxy stats socket through group haproxy.
func supplementaryGroups(uid, gid int) ([]int, error) {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("look up uid %d: %w", uid, err)
	}
	names, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("groups of %s: %w", account.Username, err)
	}
	groups := make([]int, 0, len(names)+1)
	groups = append(groups, gid)
	for _, name := range names {
		id, err := strconv.Atoi(name)
		if err != nil {
			return nil, fmt.Errorf("group id %q: %w", name, err)
		}
		groups = append(groups, id)
	}
	return groups, nil
}

type identitySwitch struct {
	setgroups func([]int) error
	setgid    func(int) error
	setuid    func(int) error
}

// apply changes the user last: after setuid the process may not touch groups.
func (s identitySwitch) apply(uid, gid int, groups []int) error {
	if err := s.setgroups(groups); err != nil {
		return err
	}
	if err := s.setgid(gid); err != nil {
		return err
	}
	return s.setuid(uid)
}
