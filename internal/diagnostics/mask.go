// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"strings"
)

// MaskEasyWAFEnvLine returns a single line with known secrets replaced (for support bundles).
func MaskEasyWAFEnvLine(line string) string {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "#") {
		return line
	}
	key, _, ok := strings.Cut(trim, "=")
	if !ok {
		return line
	}
	key = strings.TrimSpace(key)
	if secretEnvKey(key) {
		return key + "=***MASKED***"
	}
	switch key {
	case "DATABASE_URL":
		// Query parameters and non-URL DSNs may carry passwords too. A support
		// bundle does not need database topology, so mask the entire value.
		return key + "=***MASKED***"
	default:
		return line
	}
}

func secretEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	for _, marker := range []string{"PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "PRIVATE_KEY", "API_KEY", "ACCESS_KEY", "LICENSE_KEY"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// MaskEasyWAFEnvContent applies MaskEasyWAFEnvLine to every line.
func MaskEasyWAFEnvContent(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	for i := range lines {
		lines[i] = MaskEasyWAFEnvLine(lines[i])
	}
	return []byte(strings.Join(lines, "\n"))
}

// MaskHAProxyConfigContent removes forward-auth targets from a diagnostic copy
// of haproxy.cfg. Query strings commonly contain API keys, and the endpoint is
// not needed to understand the surrounding rendered policy.
func MaskHAProxyConfigContent(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	const directive = "lua.easywaf_auth"
	for i, line := range lines {
		pos := strings.Index(line, directive)
		if pos < 0 {
			continue
		}
		quote := strings.IndexByte(line[pos+len(directive):], '"')
		if quote < 0 {
			continue
		}
		start := pos + len(directive) + quote + 1
		end := strings.IndexByte(line[start:], '"')
		if end < 0 {
			// Fail closed for a malformed generated line.
			lines[i] = line[:start] + "***MASKED***"
			continue
		}
		lines[i] = line[:start] + "***MASKED***" + line[start+end:]
	}
	return []byte(strings.Join(lines, "\n"))
}
