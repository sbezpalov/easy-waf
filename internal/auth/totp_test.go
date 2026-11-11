// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA1 secret "12345678901234567890", last 6 digits.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPRFCVectors(t *testing.T) {
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := TOTPCode(rfcSecret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: %q %v, want %q", unix, got, err, want)
		}
	}
}

func TestVerifyTOTPSkewAndReplay(t *testing.T) {
	now := time.Unix(1111111109, 0)
	step, ok := VerifyTOTP(rfcSecret, "081804", now.Add(25*time.Second), 0)
	if !ok || step != 1111111109/30 {
		t.Fatalf("one step of skew: %d %v", step, ok)
	}
	if _, ok := VerifyTOTP(rfcSecret, "081804", now, step); ok {
		t.Fatal("replayed step accepted")
	}
	if _, ok := VerifyTOTP(rfcSecret, "081804", now.Add(2*time.Minute), 0); ok {
		t.Fatal("stale code accepted")
	}
	if _, ok := VerifyTOTP(rfcSecret, "08180", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(3)
	if err != nil || len(codes) != 3 || len(codes[0]) != 19 {
		t.Fatalf("%v %v", codes, err)
	}
	if HashRecoveryCode(codes[0]) != HashRecoveryCode(" "+codes[0][:4]+codes[0][5:]+" ") {
		t.Fatal("normalisation")
	}
	if IsTOTPCode(codes[0]) || !IsTOTPCode("012345") {
		t.Fatal("IsTOTPCode")
	}
}
