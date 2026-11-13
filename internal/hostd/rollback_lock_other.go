// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import (
	"fmt"
	"sync"
)

// Development-only fallback. The appliance ships only on Linux, where flock
// also coordinates with the standalone timer process.
var rollbackOperationMu sync.Mutex

func lockRollback(wait bool) (func(), error) {
	if wait {
		rollbackOperationMu.Lock()
	} else if !rollbackOperationMu.TryLock() {
		return nil, fmt.Errorf("network/firewall operation busy; retry after it completes")
	}
	return rollbackOperationMu.Unlock, nil
}
