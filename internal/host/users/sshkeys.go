// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// ValidateSSHPublicKeys checks authorized_keys lines before writing.
//
// This is the API-side (advisory) copy of the check. The same validation runs
// again inside easy-waf-hostd before anything reaches disk — see
// hostspec.ValidateAuthorizedKeysContent — so a compromised easy-waf-api cannot
// bypass it by talking to the broker socket directly.
func ValidateSSHPublicKeys(keys []string) error {
	return hostspec.ValidateSSHPublicKeys(keys)
}
