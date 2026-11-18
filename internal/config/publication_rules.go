// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
)

const (
	MaxPublicationRules = 16
	RuleCount           = "count"
	RuleBlock           = "block"
	RulePass            = "pass"
)

// PublicationRule is evaluated in its position in Application.PolicyRules.
type PublicationRule struct {
	ID     string           `json:"id"`
	Action string           `json:"action"`
	Match  PublicationMatch `json:"match"`
}

func (r *PublicationRule) UnmarshalJSON(data []byte) error {
	type rule PublicationRule
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode((*rule)(r))
}

// PublicationMatch combines populated fields with AND. Each CIDR or method
// list matches any one entry within that field.
type PublicationMatch struct {
	PathPrefix   string   `json:"path_prefix,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	SourceCIDRs  []string `json:"source_cidrs,omitempty"`
	Header       string   `json:"header,omitempty"`
	HeaderPrefix string   `json:"header_prefix,omitempty"`
}

var publicationRuleID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
var publicationMethod = regexp.MustCompile(`^[A-Z]{1,24}$`)

func ValidatePublicationRules(rules []PublicationRule) error {
	if len(rules) > MaxPublicationRules {
		return fmt.Errorf("policy_rules: at most %d rules", MaxPublicationRules)
	}
	ids := make(map[string]bool, len(rules))
	for i, rule := range rules {
		field := fmt.Sprintf("policy_rules[%d]", i)
		if !publicationRuleID.MatchString(rule.ID) || ids[rule.ID] {
			return fmt.Errorf("%s.id: expected a unique ID of 1–32 lowercase letters, digits, underscores or hyphens, starting with a letter or digit", field)
		}
		ids[rule.ID] = true
		switch rule.Action {
		case RuleCount, RuleBlock, RulePass:
		default:
			return fmt.Errorf("%s.action: expected count, block or pass", field)
		}
		if err := validatePublicationMatch(field+".match", rule.Match); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicationMatch(field string, m PublicationMatch) error {
	if m.PathPrefix == "" && len(m.Methods) == 0 && len(m.SourceCIDRs) == 0 && m.Header == "" {
		return fmt.Errorf("%s: at least one condition is required; use / to match every path", field)
	}
	if m.PathPrefix != "" && m.PathPrefix != "/" {
		if err := validateExposurePath(field+".path_prefix", m.PathPrefix); err != nil {
			return err
		}
	}
	if len(m.Methods) > 16 || len(m.SourceCIDRs) > 16 {
		return fmt.Errorf("%s: at most 16 methods and 16 source networks", field)
	}
	for _, method := range m.Methods {
		if !publicationMethod.MatchString(method) {
			return fmt.Errorf("%s.methods: expected an uppercase HTTP method", field)
		}
	}
	for _, source := range m.SourceCIDRs {
		addr, addrErr := netip.ParseAddr(source)
		if _, prefixErr := netip.ParsePrefix(source); prefixErr != nil && (addrErr != nil || addr.Zone() != "") {
			return fmt.Errorf("%s.source_cidrs: expected an IP address or CIDR", field)
		}
	}
	if err := validateHeaderName(field+".header", m.Header, m.HeaderPrefix != ""); err != nil {
		return err
	}
	return validateValuePrefix(field+".header_prefix", m.HeaderPrefix)
}
