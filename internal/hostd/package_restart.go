// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	packageRestartTimeout = 35 * time.Minute
	// Leave a full control-command budget plus cleanup time after lock wait.
	packageRestartLockTimeout = packageRestartTimeout - hostCommandTimeout - time.Minute
)

// RunPostUpgradeRestart runs outside the installing transaction: in a separate
// maintenance service, or after the outer source installer finishes. Waiting in
// postinst/the broker's cgroup would deadlock or kill its own dpkg. The running
// old broker need not understand this new helper protocol.
func RunPostUpgradeRestart() error {
	ctx, cancel := packageRestartWaitContext()
	defer cancel()
	logOp("waiting for APT/dpkg locks before post-upgrade broker restart")
	return restartBrokerAfterPackages(ctx, DefaultRunner, acquireDpkgLocks)
}

func packageRestartWaitContext() (context.Context, context.CancelFunc) {
	base, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(base, packageRestartLockTimeout)
	return ctx, func() { cancel(); stop() }
}

func restartBrokerAfterPackages(ctx context.Context, runner CommandRunner, acquire func(context.Context) (func() error, error)) (err error) {
	release, err := acquire(ctx)
	if err != nil {
		return fmt.Errorf("wait for package managers: %w", err)
	}
	defer func() { err = errors.Join(err, release()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Hold both locks across the job: merely observing an old PID/lock exit
	// leaves a gap in which a second APT could start before systemd stops hostd.
	// The acquisition deadline must not expire just after submitting a job:
	// killing its systemctl client does not cancel the manager's restart job.
	// Give this phase its own complete bounded wait before releasing the lease.
	_, stderr, code, runErr := runCmd(context.WithoutCancel(ctx), runner, binSystemctl, "try-restart", "easy-waf-hostd.service")
	if runErr != nil || code != 0 {
		return fmt.Errorf("post-upgrade broker restart: %w", commandFailure(stderr, code, runErr))
	}
	return nil
}
