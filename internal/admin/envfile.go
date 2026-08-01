package admin

import (
	"os"
	"strings"
)

// UpsertEnvKey sets or replaces KEY=value in a line-oriented env file (e.g. /etc/easy-waf/easy-waf.env).
// Preserves comments and blank lines. Creates the file if missing.
func UpsertEnvKey(path, key, value string) error {
	var lines []string
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	found := false
	if len(b) > 0 {
		raw := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
		for _, line := range raw {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				lines = append(lines, line)
				continue
			}
			if strings.HasPrefix(trimmed, key+"=") {
				lines = append(lines, key+"="+value)
				found = true
				continue
			}
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	out := strings.Join(lines, "\n")
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0o600)
}

// ReadEnvKey returns the value for KEY in a line-oriented env file (first match). Empty if missing or unreadable.
func ReadEnvKey(path, key string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	prefix := key + "="
	raw := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):]), nil
		}
	}
	return "", nil
}

// RemoveEnvKey drops KEY=value lines (e.g. deprecated EASY_WAF_LISTEN after split HTTP/HTTPS).
func RemoveEnvKey(path, key string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	prefix := key + "="
	raw := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			continue
		}
		lines = append(lines, line)
	}
	out := strings.Join(lines, "\n")
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0o600)
}
