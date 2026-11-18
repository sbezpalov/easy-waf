// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidatePublicationRules(t *testing.T) {
	for _, tc := range []struct {
		name, payload, invalid string
	}{
		{"valid", `[{"id":"watch","action":"count","match":{"path_prefix":"/api/","methods":["GET","POST"],"source_cidrs":["192.0.2.1","2001:db8::/32"],"header":"User-Agent","header_prefix":"Example Client "}}]`, ""},
		{"unknown matcher", `[{"id":"deny","action":"block","match":{"path_prefix":"/","country":"NL"}}]`, "unknown field"},
		{"empty match", `[{"id":"deny","action":"block","match":{}}]`, "condition"},
		{"ambiguous rule ID", `[{"id":"a|b","action":"block","match":{"path_prefix":"/"}}]`, ".id"},
		{"duplicate", `[{"id":"a","action":"count","match":{"path_prefix":"/"}},{"id":"a","action":"block","match":{"path_prefix":"/"}}]`, ".id"},
		{"unknown action", `[{"id":"a","action":"redirect","match":{"path_prefix":"/"}}]`, ".action"},
		{"header required", `[{"id":"a","action":"count","match":{"methods":["GET"],"header_prefix":"Client "}}]`, ".header"},
		{"no HAProxy quoting", `[{"id":"a","action":"block","match":{"header":"User-Agent","header_prefix":"\" if TRUE"}}]`, ".header_prefix"},
		{"no HAProxy condition", `[{"id":"a","action":"block","match":{"path_prefix":"/api || TRUE"}}]`, ".path_prefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rules []PublicationRule
			err := json.Unmarshal([]byte(tc.payload), &rules)
			if err == nil {
				err = ValidatePublicationRules(rules)
			}
			if tc.invalid == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.invalid) {
				t.Fatalf("want error containing %q, got %v", tc.invalid, err)
			}
		})
	}
}
