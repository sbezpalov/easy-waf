// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// Mutating runners own process lifetime, publish PID metadata and join output
// callbacks before returning. A plain CommandRunner cannot silently fall back
// to an untracked package subprocess.
type aptCommandRunner interface {
	RunApt(context.Context, string, []string, func(string) error) (int, error)
}

type aptExecution func(context.Context, func(string) error) (int, error)

func aptMutationArgs(action string) ([]string, error) {
	args := []string{"-o", "Dpkg::Use-Pty=0", "-o", "DPkg::Lock::Timeout=120"}
	switch action {
	case "upgrade", "autoremove":
		args = append([]string{"-y"}, args...)
	case "update", "clean":
	default:
		return nil, errors.New("unknown apt mutation")
	}
	return append(args, action), nil
}

func runAptMutation(ctx context.Context, runner CommandRunner, action string, emit func(string) error) (int, error) {
	args, err := aptMutationArgs(action)
	if err != nil {
		return 1, err
	}
	tracked, ok := runner.(aptCommandRunner)
	if !ok {
		return 1, errors.New("APT runner does not support tracked execution")
	}
	return tracked.RunApt(ctx, binAptGet, args, emit)
}

func runAptPrimary(ctx context.Context, record *aptActionRecord, action string, execute aptExecution, emit func(string) error) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, aptCommandTimeout)
	defer cancel()
	logFile, err := createAptActionLog(aptActionLogPath())
	publishAptActionLog(record, err)
	if err != nil {
		logOp("apt %s: log file: %v", action, err)
	}
	logSink := aptLogSink{err: err}
	if logFile != nil {
		logSink.file = logFile
	}
	emitLine := func(line string) error {
		logSink.line(line)
		return emit(line)
	}
	_ = emitLine(fmt.Sprintf("==> starting apt-get %s ...", action))
	emitDpkgLockHint(emitLine)
	code, runErr := execute(ctx, emitLine)
	if logErr := logSink.close(); logErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("apt action log incomplete (command exit code %d): %w", code, logErr))
	}
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
		if code == 0 {
			code = 1
		}
	}
	finishAptAction(record, code, errMsg)
	return code, runErr
}

func aptBusyMessage(record *aptActionRecord) string {
	if active, _, message := aptRecordSnapshot(record); active && message != "" {
		return message
	}
	if record.action != "" {
		return fmt.Sprintf("APT %s is already in progress; retry after it finishes", record.action)
	}
	return "APT operation is already in progress; retry after it finishes"
}

const (
	synchronousAptOutputLimit = 1 << 20
	synchronousAptTailLimit   = 4096
	aptExcerptNotice          = "[response output truncated; inspect the saved apt action log]\n"
)

func dispatchAptSynchronous(ctx context.Context, runner CommandRunner, action string) Response {
	record, started, err := acquireAptAction(action, aptSynchronous)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	defer releaseAptAction(record)
	if !started {
		return failResp(aptBusyMessage(record), 1)
	}
	var output bytes.Buffer
	var tail string
	truncated := false
	emit := func(line string) error {
		tail += line + "\n"
		if len(tail) > synchronousAptTailLimit {
			tail = tail[len(tail)-synchronousAptTailLimit:]
		}
		if !truncated {
			if len(line)+1 > synchronousAptOutputLimit-len(aptExcerptNotice)-output.Len() {
				truncated = true
			} else {
				_, _ = output.WriteString(line + "\n")
			}
		}
		return nil
	}
	code, runErr := runAptPrimary(ctx, record, action, func(ctx context.Context, emitLine func(string) error) (int, error) {
		code, err := runAptOutput(ctx, func(ctx context.Context, trackedEmit func(string) error) (int, error) {
			return runAptMutation(ctx, runner, action, trackedEmit)
		}, emitLine)
		// The heartbeat is joined before reading the callback-owned tail.
		if err != nil || code != 0 {
			err = commandFailure([]byte(tail), code, err)
		}
		return code, err
	}, emit)
	if truncated {
		_, _ = output.WriteString(aptExcerptNotice)
	}
	resp := okResp(output.Bytes(), nil, code)
	if runErr != nil {
		resp.Error = runErr.Error()
	}
	return resp
}
