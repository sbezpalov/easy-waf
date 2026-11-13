// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAptMissingBookkeepingIsNotInspectionFailure(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	if _, err := recoverAptActionProcess(); !errors.Is(err, errNoSavedAptProcess) {
		t.Fatalf("missing bookkeeping not distinguished: %v", err)
	}
	if active, code, message := aptActionSnapshot(); active || code != 0 || message != "" {
		t.Fatalf("no saved action became a verification failure: active=%v code=%d error=%q", active, code, message)
	}
}

func TestAptPIDMetadataParsingAndBounds(t *testing.T) {
	const bootID = "12345678-1234-1234-1234-123456789abc"
	for _, input := range []string{"123\n", "0\n", "123\nv1 " + bootID + " 42\n"} {
		identity, err := parseAptActionPID([]byte(input))
		wantPID := 123
		if input == "0\n" {
			wantPID = 0
		}
		if err != nil || identity.pid != wantPID {
			t.Fatalf("valid PID metadata rejected: %+v %v", identity, err)
		}
		if strings.Contains(input, "v1") && (identity.bootID != bootID || identity.startTicks != 42) {
			t.Fatalf("process epoch lost: %+v", identity)
		}
	}
	for _, input := range []string{"", "123junk", "123 trailing", "123\nv2 " + bootID + " 42", "123\nv1 bad-uuid 42", "123\nv1 " + bootID + " -1", "123\nv1 " + bootID + " 18446744073709551616", "123\nv1 " + bootID + " 42 extra"} {
		if _, err := parseAptActionPID([]byte(input)); err == nil {
			t.Fatalf("malformed PID metadata accepted: %q", input)
		}
	}
	if data, err := readBoundedAptMetadata(strings.NewReader(strings.Repeat("x", maxAptPIDBytes)), maxAptPIDBytes); err != nil || len(data) != maxAptPIDBytes {
		t.Fatalf("exact metadata limit rejected: length=%d err=%v", len(data), err)
	}
	if _, err := readBoundedAptMetadata(strings.NewReader(strings.Repeat("x", maxAptPIDBytes+1)), maxAptPIDBytes); err == nil {
		t.Fatal("oversized metadata prefix accepted")
	}
}

func TestAptPIDWriterKeepsLegacyLeadingPID(t *testing.T) {
	overrideAptActionLogForTest(t)
	if err := writeAptActionPID(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	data, err := readAptActionPID()
	if err != nil {
		t.Fatal(err)
	}
	var legacyPID int
	if _, err := fmt.Sscanf(string(data), "%d", &legacyPID); err != nil || legacyPID != os.Getpid() {
		t.Fatalf("older broker cannot read the leading PID: %d %v", legacyPID, err)
	}
	if err := writeAptActionPID(0); err == nil {
		t.Fatal("publisher accepted an invalid process PID")
	}
}

func TestAptMalformedPIDBlocksNewActionUntilInspectionResolves(t *testing.T) {
	for _, input := range []string{"not-a-pid", strings.Repeat("1", maxAptPIDBytes+1)} {
		t.Run(fmt.Sprintf("bytes_%d", len(input)), func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			defer resetAptUpgradeState()
			if err := storeAptActionPID([]byte(input)); err != nil {
				t.Fatal(err)
			}
			if started, err := aptActionTryStart(); err != nil || started {
				t.Fatalf("unverifiable metadata allowed a new action: %v %v", started, err)
			}
			if active, code, message := aptActionSnapshot(); !active || code != -1 || !strings.Contains(message, "cannot verify") {
				t.Fatalf("verification error hidden: active=%v code=%d message=%q", active, code, message)
			}
			if err := storeAptActionPID([]byte("0\n")); err != nil {
				t.Fatal(err)
			}
			if started, err := aptActionTryStart(); err != nil || !started {
				t.Fatalf("resolved stale metadata blocked a new action: %v %v", started, err)
			}
		})
	}
}

func TestAptUnverifiablePIDRetainsReservationAndReportsError(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	if err := os.Mkdir(aptActionPIDPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	active, code, message := aptActionSnapshot()
	if !active || code != -1 || !strings.Contains(message, "cannot verify") {
		t.Fatalf("unverifiable PID released the reservation: active=%v code=%d error=%q", active, code, message)
	}
	if started, err := aptActionTryStart(); err != nil || started {
		t.Fatalf("unverifiable PID allowed another action: started=%v err=%v", started, err)
	}
	var output bytes.Buffer
	dispatchAptStream(&output, "upgrade")
	events := readStreamEvents(t, &output)
	last := events[len(events)-1]
	if last.Code != -1 || !strings.Contains(last.Error, "cannot verify") {
		t.Fatalf("follower hid verification failure: %+v", last)
	}
	if err := os.Remove(aptActionPIDPath()); err != nil {
		t.Fatal(err)
	}
	if active, code, message := aptActionSnapshot(); active || code != -1 || message == "" {
		t.Fatalf("recovery did not resolve after access restored: active=%v code=%d error=%q", active, code, message)
	}
}
