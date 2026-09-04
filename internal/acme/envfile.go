// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ApplyEnvFromFile parses KEY=value lines (shell-style, # comments) and sets os.Getenv.
// Cleanup restores previous values for those keys. Path must be readable only by the ACME worker user.
func ApplyEnvFromFile(path string) (cleanup func(), err error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("dns: credentials env file path is empty")
	}
	m, err := parseEnvFile(path)
	if err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("dns: no variables in env file %s", path)
	}
	prev := make(map[string]string, len(m))
	for k := range m {
		prev[k] = os.Getenv(k)
	}
	applied := make([]string, 0, len(m))
	for k, v := range m {
		if e := os.Setenv(k, v); e != nil {
			for _, kk := range applied {
				restoreOne(kk, prev[kk])
			}
			return nil, fmt.Errorf("setenv %s: %w", k, e)
		}
		applied = append(applied, k)
	}
	return func() {
		for _, k := range applied {
			restoreOne(k, prev[k])
		}
	}, nil
}

func restoreOne(k, old string) {
	if old == "" {
		_ = os.Unsetenv(k)
	} else {
		_ = os.Setenv(k, old)
	}
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		if key != "" {
			out[key] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
