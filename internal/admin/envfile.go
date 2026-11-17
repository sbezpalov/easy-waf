// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
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

// LookupEnvKey reads the last KEY=value entry from a line-oriented appliance
// env file. Matching outer quotes are removed without evaluating the value.
func LookupEnvKey(path, key string) (value string, found bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	prefix := key + "="
	raw := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			value = strings.TrimSpace(trimmed[len(prefix):])
			if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
			found = true
		}
	}
	return value, found, nil
}

// ResolveDatabaseURL applies the CLI override, the appliance file, then the
// inherited environment. An explicit empty file entry disables the fallback.
func ResolveDatabaseURL(envFile, override string) (string, error) {
	if value := strings.TrimSpace(override); value != "" {
		return value, nil
	}
	value, found, err := LookupEnvKey(envFile, "DATABASE_URL")
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read %s: %w", envFile, err)
	}
	if found {
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("DATABASE_URL is empty in %s", envFile)
		}
		return value, nil
	}
	if value := strings.TrimSpace(os.Getenv("DATABASE_URL")); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("DATABASE_URL not set: put DATABASE_URL in %s, set it in the environment, or use -database-url", envFile)
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
