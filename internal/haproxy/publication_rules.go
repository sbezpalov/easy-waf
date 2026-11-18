// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"fmt"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// publicationRules follows path exposure and required-header checks, before the
// IP allow shortcut. A pass ends this list and resumes the existing checks.
func publicationRules(app AppRender, host string, skipACME bool) string {
	var out strings.Builder
	for i, rule := range app.Application.PolicyRules {
		acl := fmt.Sprintf("policy_%s_%d", app.ACLTag, i)
		m := rule.Match
		condition := host + " !{ var(txn.publication_done) -m found }"
		if m.PathPrefix != "" {
			path := strings.TrimRight(m.PathPrefix, "/")
			if path != "" {
				fmt.Fprintf(&out, "\n\tacl %s_path path -m str %s", acl, path)
			}
			fmt.Fprintf(&out, "\n\tacl %s_path path_beg %s/", acl, path)
			condition += " " + acl + "_path"
		}
		if len(m.Methods) > 0 {
			fmt.Fprintf(&out, "\n\tacl %s_method method %s", acl, strings.Join(m.Methods, " "))
			condition += " " + acl + "_method"
		}
		if len(m.SourceCIDRs) > 0 {
			fmt.Fprintf(&out, "\n\tacl %s_src src %s", acl, strings.Join(m.SourceCIDRs, " "))
			condition += " " + acl + "_src"
		}
		if m.Header != "" {
			match := "-m found"
			if m.HeaderPrefix != "" {
				match = fmt.Sprintf("-m beg -- \"%s\"", m.HeaderPrefix)
			}
			fmt.Fprintf(&out, "\n\tacl %s_header req.fhdr(%s) %s", acl, m.Header, match)
			condition += " " + acl + "_header"
		}
		condition += acmeSuffix(skipACME)
		fmt.Fprintf(&out, "\n\thttp-request capture str(policy-%s:%s) id %d if %s", rule.Action, rule.ID, i+2, condition)
		switch rule.Action {
		case config.RuleBlock:
			fmt.Fprintf(&out, "\n\thttp-request capture str(policy_block) id 1 if %s", condition)
			fmt.Fprintf(&out, "\n\thttp-request deny deny_status 403 if %s", condition)
		case config.RulePass:
			fmt.Fprintf(&out, "\n\thttp-request set-var(txn.publication_done) bool(true) if %s", condition)
		}
	}
	return out.String()
}
