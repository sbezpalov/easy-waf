// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAptCommandCapturesOutputAndDrainsOversizedLines(t *testing.T) {
	if stream := os.Getenv("EASY_WAF_APT_OUTPUT_CHILD"); stream != "" {
		output := io.Writer(os.Stdout)
		if stream == "stderr" {
			output = os.Stderr
		}
		if stream == "normal" || stream == "failure" {
			_, _ = fmt.Fprintln(os.Stdout, "stdout-line")
			_, _ = fmt.Fprintln(os.Stderr, "stderr-line")
		} else {
			if _, err := fmt.Fprintln(output, strings.Repeat("x", 2<<20)); err != nil {
				os.Exit(90)
			}
		}
		if err := os.WriteFile(os.Getenv("EASY_WAF_APT_OUTPUT_MARKER"), []byte("finished"), 0o600); err != nil {
			os.Exit(91)
		}
		code, _ := strconv.Atoi(os.Getenv("EASY_WAF_APT_OUTPUT_EXIT"))
		os.Exit(code)
	}
	for _, stream := range []string{"normal", "failure", "stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			defer func() { _ = clearAptActionPID() }()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			fixtureDir := t.TempDir()
			marker := filepath.Join(fixtureDir, "finished")
			exit := "0"
			wantCode := 0
			captureFailure := stream == "stdout" || stream == "stderr"
			if captureFailure {
				wantCode = 1
			}
			if stream == "stderr" || stream == "failure" {
				exit, wantCode = "7", 7
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestAptCommandCapturesOutputAndDrainsOversizedLines$")
			cmd.Env = append(os.Environ(), "EASY_WAF_APT_OUTPUT_CHILD="+stream, "EASY_WAF_APT_OUTPUT_MARKER="+marker, "EASY_WAF_APT_OUTPUT_EXIT="+exit)
			// Child TestMain may allocate temporary bookkeeping before os.Exit.
			// Keep those files inside the parent's automatically cleaned fixture.
			cmd.Env = append(cmd.Env, "TMPDIR="+fixtureDir, "TMP="+fixtureDir, "TEMP="+fixtureDir)
			var lines []string
			code, err := execAptCommand(cmd, func(line string) error { lines = append(lines, line); return nil })
			if _, markerErr := os.Stat(marker); markerErr != nil {
				t.Fatalf("child never finished writing output (pipe not drained): %v; command error=%v", markerErr, err)
			}
			if code != wantCode || (err != nil) != (wantCode != 0) {
				t.Fatalf("output error/apt exit status lost: code=%d error=%v", code, err)
			}
			if captureFailure && !strings.Contains(err.Error(), "apt output") {
				t.Fatalf("capture error hidden: %v", err)
			}
			if !captureFailure && (len(lines) != 2 || !strings.Contains(strings.Join(lines, "\n"), "stdout-line") || !strings.Contains(strings.Join(lines, "\n"), "stderr-line")) {
				t.Fatalf("normal stdout/stderr lost: %v", lines)
			}
			if ctx.Err() != nil {
				t.Fatalf("child required forced termination: %v", ctx.Err())
			}
		})
	}
}

func TestAptAttachAcceptsLinesPrimaryCanCapture(t *testing.T) {
	overrideAptActionLogForTest(t)
	line := strings.Repeat("x", 128<<10)
	if err := os.WriteFile(aptActionLogPath(), []byte(line+"\nnext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readAptActionLogFrom(0)
	if err != nil || len(lines) != 2 || lines[0] != line || lines[1] != "next" {
		t.Fatalf("attach rejected a valid primary log: lines=%d error=%v", len(lines), err)
	}
	if offset != int64(len(line)+len("\nnext\n")) {
		t.Fatalf("offset=%d", offset)
	}
}
