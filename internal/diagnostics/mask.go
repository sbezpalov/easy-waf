package diagnostics

import (
	"net/url"
	"strings"
)

// MaskEasyWAFEnvLine returns a single line with known secrets replaced (for support bundles).
func MaskEasyWAFEnvLine(line string) string {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "#") {
		return line
	}
	key, val, ok := strings.Cut(trim, "=")
	if !ok {
		return line
	}
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	switch key {
	case "CROWDSEC_LAPI_KEY", "EASY_WAF_JWT_SECRET", "EASY_WAF_ADMIN_TOKEN":
		return key + "=***MASKED***"
	case "DATABASE_URL":
		return key + "=" + maskDatabaseURL(val)
	default:
		return line
	}
}

func maskDatabaseURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return "***MASKED***"
	}
	user := u.User.Username()
	pass, hasPass := u.User.Password()
	if !hasPass || pass == "" {
		return s
	}
	// Avoid url.URL.String() escaping of '*' in the password placeholder.
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	b.WriteString(user)
	b.WriteString(":***MASKED***@")
	b.WriteString(u.Host)
	b.WriteString(u.EscapedPath())
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.Fragment)
	}
	return b.String()
}

// MaskEasyWAFEnvContent applies MaskEasyWAFEnvLine to every line.
func MaskEasyWAFEnvContent(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	for i := range lines {
		lines[i] = MaskEasyWAFEnvLine(lines[i])
	}
	return []byte(strings.Join(lines, "\n"))
}
