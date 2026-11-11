// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1; authenticator apps expect it.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const totpPeriod = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit base32 TOTP secret.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI is the otpauth:// URI authenticator apps import.
func TOTPURI(issuer, account, secret string) string {
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) +
		"?secret=" + secret + "&issuer=" + url.QueryEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
}

func totpCode(key []byte, step int64) string {
	if step < 0 {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // checked non-negative above
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 0x0f
	v := (uint32(h[o]&0x7f)<<24 | uint32(h[o+1])<<16 | uint32(h[o+2])<<8 | uint32(h[o+3])) % 1000000
	return fmt.Sprintf("%06d", v)
}

// TOTPCode returns the code for secret at t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return totpCode(key, t.Unix()/totpPeriod), nil
}

// VerifyTOTP checks code against the steps around now (one step of clock skew
// each way) that are later than lastStep, and returns the matching step.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-1); d <= 1; d++ {
		st := cur + d
		if st <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(key, st)), []byte(code)) == 1 {
			return st, true
		}
	}
	return 0, false
}

// IsTOTPCode reports whether s looks like a 6-digit code rather than a recovery code.
func IsTOTPCode(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// GenerateRecoveryCodes returns n random one-time codes (80 bits each).
func GenerateRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	for range n {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s := strings.ToLower(b32.EncodeToString(b))
		out = append(out, s[0:4]+"-"+s[4:8]+"-"+s[8:12]+"-"+s[12:16])
	}
	return out, nil
}

// HashRecoveryCode is the stored form of a recovery code. The codes are
// random, so a fast hash is enough; case, dashes and spaces are ignored.
func HashRecoveryCode(code string) string {
	n := strings.NewReplacer("-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(n))
	return hex.EncodeToString(sum[:])
}
