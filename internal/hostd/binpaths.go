// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

// Absolute paths for privileged tools. Never resolve these via PATH: an earlier
// writable PATH entry would otherwise become root RCE outside the opcode allowlist.
const (
	binSystemctl  = "/usr/bin/systemctl"
	binNetplan    = "/usr/sbin/netplan"
	binAptGet     = "/usr/bin/apt-get"
	binJournalctl = "/usr/bin/journalctl"
	binUseradd    = "/usr/sbin/useradd"
	binUserdel    = "/usr/sbin/userdel"
	binDu         = "/usr/bin/du"
	binNft        = "/usr/sbin/nft"
)
