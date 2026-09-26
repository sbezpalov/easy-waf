// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import "testing"

func TestValidateNftRuleset(t *testing.T) {
	ok := []string{
		"table inet easy_waf {\n\tchain input { type filter hook input priority 0; tcp dport { 80, 443 } accept }\n}\n",
		"# include \"/etc/shadow\" is only a comment here\ntable inet t { }\n",
		"table inet t { comment \"do not include me\"; }\n",
		"define includes = { 10.0.0.1 }\ntable inet t { }\n",
	}
	for _, in := range ok {
		if err := ValidateNftRuleset([]byte(in)); err != nil {
			t.Errorf("rejected valid ruleset %q: %v", in, err)
		}
	}
	bad := []string{
		"include \"/etc/shadow\"\n",
		"table inet t { }\n  include \"/root/.ssh/id_ed25519\"",
		"table inet t { } ;include \"/etc/shadow\"",
		"table inet t { }\n\tinclude\t\"/etc/*\"\n",
		"include",
		"table inet t { }\x00",
	}
	for _, in := range bad {
		if err := ValidateNftRuleset([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}
