// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"strings"
)

// MaskEasyWAFEnvLine returns a single line with known secrets replaced (for support bundles).
func MaskEasyWAFEnvLine(line string) string {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
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

// MaskEasyWAFEnvContent masks complete sensitive EnvironmentFile values,
// including quoted newlines and backslash continuations, without evaluating them.
func MaskEasyWAFEnvContent(raw []byte) []byte {
	var out strings.Builder
	var state envValueState
	continuing := false
	for _, chunk := range strings.SplitAfter(string(raw), "\n") {
		line, newline := strings.CutSuffix(chunk, "\n")
		if continuing {
			continuing = state.continues(line)
			continue
		}
		masked := MaskEasyWAFEnvLine(line)
		out.WriteString(masked)
		if newline {
			out.WriteByte('\n')
		}
		if masked != line {
			_, value, ok := strings.Cut(line, "=")
			if ok {
				state = envValueStart
				continuing = state.continues(value)
			}
		}
	}
	return []byte(out.String())
}

// Only value boundaries are needed for redaction, not decoded values. Quotes
// start at a value boundary; quotes inside an unquoted word remain literal.
type envValueState uint8

const (
	envValueStart envValueState = iota
	envValueUnquoted
	envValueSingleQuote
	envValueDoubleQuote
	envValueEscape
	envValueDoubleEscape
)

func (s *envValueState) continues(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch *s {
		case envValueStart:
			switch c {
			case ' ', '\t', '\r':
			case '\'':
				*s = envValueSingleQuote
			case '"':
				*s = envValueDoubleQuote
			case '\\':
				*s = envValueEscape
			default:
				*s = envValueUnquoted
			}
		case envValueUnquoted:
			if c == '\\' {
				*s = envValueEscape
			}
		case envValueSingleQuote:
			if c == '\'' {
				*s = envValueStart
			}
		case envValueDoubleQuote:
			switch c {
			case '\\':
				*s = envValueDoubleEscape
			case '"':
				*s = envValueStart
			}
		case envValueEscape:
			*s = envValueUnquoted
		case envValueDoubleEscape:
			*s = envValueDoubleQuote
		}
	}
	// A trailing escape consumes the physical newline. An open quote keeps it
	// inside this value; an unterminated secret therefore stays masked to EOF.
	switch *s {
	case envValueEscape:
		*s = envValueUnquoted
		return true
	case envValueDoubleEscape:
		*s = envValueDoubleQuote
		return true
	case envValueSingleQuote, envValueDoubleQuote:
		return true
	default:
		return false
	}
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
