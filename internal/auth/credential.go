// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import "strings"

// AuthorizationCredential returns the secret from an Authorization header.
// RFC 6750 treats the Bearer scheme as case-insensitive. A value with no
// scheme is returned unchanged so clients that already send a raw token
// keep working.
func AuthorizationCredential(header string) string {
	h := strings.TrimSpace(header)
	const scheme = "bearer "
	if len(h) >= len(scheme) && strings.EqualFold(h[:len(scheme)], scheme) {
		return strings.TrimSpace(h[len(scheme):])
	}
	return h
}
