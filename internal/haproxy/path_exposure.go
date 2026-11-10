// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// pathExposure is the HAProxy view of Application.PathPolicy.
// Strings are already validated; the template prints them as single tokens.
type pathExposure struct {
	Allowlist  bool
	AllowExact string
	AllowDirs  string
	FrontPaths []exposurePath
	Headers    []exposureCheck
	// ClientTimeouts are emitted on the frontend. HAProxy 2.8 rejects
	// set-timeout client in a backend; only server and tunnel are valid there.
	ClientTimeouts []exposureTimeout
	BackPaths      []exposurePath
	Timeouts       []exposureTimeout
	Rates          []exposureRate
	Strip          []string
	AppClient      int
	AppServer      int
}

type exposurePath struct {
	Name  string
	Exact string
	Dir   string
}

type exposureCheck struct {
	PathName  string
	CheckName string
	Header    string
	Mode      string // found, prefix, file
	Prefix    string
	File      string
}

type exposureTimeout struct {
	PathName string
	Client   int
	Server   int
}

type exposureRate struct {
	PathName string
	Unless   string
	Stick    string
	Limit    int
}

type policyRule struct {
	index  int
	prefix string
	exact  string
	dir    string
	rule   config.PathRule
}

func buildPathExposure(app config.Application, aclTag, stateDir string) (pathExposure, error) {
	var out pathExposure
	p := app.PathPolicy
	if p == nil {
		return out, nil
	}
	if p.Mode == config.PathModeAllowlist {
		out.Allowlist = true
		out.AllowExact = exactPaths(p.Allow)
		out.AllowDirs = dirPrefixes(p.Allow)
	}
	out.AppClient = p.ClientTimeoutSec
	out.AppServer = p.ServerTimeoutSec

	rules := make([]policyRule, 0, len(p.Rules))
	for i, r := range p.Rules {
		if !ruleDoesSomething(r) {
			continue
		}
		prefix := strings.TrimRight(strings.TrimSpace(r.PathPrefix), "/")
		rules = append(rules, policyRule{
			index:  i,
			prefix: prefix,
			exact:  prefix,
			dir:    prefix + "/",
			rule:   r,
		})
	}
	// Longest prefix first so a more specific rule wins the rate counter and,
	// when timeouts are emitted in reverse, the final set-timeout.
	sort.SliceStable(rules, func(i, j int) bool {
		if len(rules[i].prefix) != len(rules[j].prefix) {
			return len(rules[i].prefix) > len(rules[j].prefix)
		}
		return rules[i].index < rules[j].index
	})

	names := make([]string, len(rules))
	for i := range rules {
		names[i] = fmt.Sprintf("app_%s_pp_%d", aclTag, i)
	}

	var front []exposurePath
	var back []exposurePath
	frontSeen := map[string]bool{}
	backSeen := map[string]bool{}
	addFront := func(i int) {
		if frontSeen[names[i]] {
			return
		}
		frontSeen[names[i]] = true
		front = append(front, exposurePath{Name: names[i], Exact: rules[i].exact, Dir: rules[i].dir})
	}
	addBack := func(i int) {
		if backSeen[names[i]] {
			return
		}
		backSeen[names[i]] = true
		back = append(back, exposurePath{Name: names[i], Exact: rules[i].exact, Dir: rules[i].dir})
	}

	stripSeen := map[string]struct{}{}
	var rateNames []string
	for i, r := range rules {
		if r.rule.RequireHeader != "" {
			addFront(i)
			mode := "found"
			if r.rule.RequireValuePrefix != "" {
				mode = "prefix"
			}
			out.Headers = append(out.Headers, exposureCheck{
				PathName:  names[i],
				CheckName: names[i] + "_hdr",
				Header:    r.rule.RequireHeader,
				Mode:      mode,
				Prefix:    r.rule.RequireValuePrefix,
			})
		}
		if r.rule.EdgeTokenHeader != "" && r.rule.EdgeTokenConfigured {
			file, err := config.EdgeTokenFile(stateDir, app.ID, r.rule.PathPrefix, r.rule.EdgeTokenHeader)
			if err != nil {
				return pathExposure{}, err
			}
			if err := config.ValidateConfigFilePath("edge token file", file, false); err != nil {
				return pathExposure{}, err
			}
			st, err := os.Stat(file)
			if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
				return pathExposure{}, fmt.Errorf("application %q: edge token for %s %s is not available", app.ID, r.rule.PathPrefix, r.rule.EdgeTokenHeader)
			}
			addFront(i)
			out.Headers = append(out.Headers, exposureCheck{
				PathName:  names[i],
				CheckName: names[i] + "_edge",
				Header:    r.rule.EdgeTokenHeader,
				Mode:      "file",
				File:      file,
			})
			if _, ok := stripSeen[r.rule.EdgeTokenHeader]; !ok {
				stripSeen[r.rule.EdgeTokenHeader] = struct{}{}
				out.Strip = append(out.Strip, r.rule.EdgeTokenHeader)
			}
		}
		if r.rule.ServerTimeoutSec > 0 {
			addBack(i)
		}
		if r.rule.RatePer10s > 0 {
			addBack(i)
			rateNames = append(rateNames, names[i])
		}
	}
	out.FrontPaths = front
	out.BackPaths = back

	// Shortest prefix first: a later set-timeout from a longer prefix replaces it.
	for i := len(rules) - 1; i >= 0; i-- {
		r := rules[i]
		if r.rule.ClientTimeoutSec > 0 {
			out.ClientTimeouts = append(out.ClientTimeouts, exposureTimeout{
				PathName: names[i],
				Client:   r.rule.ClientTimeoutSec,
			})
		}
		if r.rule.ServerTimeoutSec > 0 {
			out.Timeouts = append(out.Timeouts, exposureTimeout{
				PathName: names[i],
				Server:   r.rule.ServerTimeoutSec,
			})
		}
	}
	for i, r := range rules {
		if r.rule.RatePer10s <= 0 {
			continue
		}
		var unless []string
		for _, earlier := range rateNames {
			if earlier == names[i] {
				break
			}
			unless = append(unless, "!"+earlier)
		}
		out.Rates = append(out.Rates, exposureRate{
			PathName: names[i],
			Unless:   strings.Join(unless, " "),
			Stick:    stickTableName(aclTag, i),
			Limit:    r.rule.RatePer10s,
		})
	}
	return out, nil
}

func maxClientTimeout(apps []AppRender) int {
	longest := 0
	for _, a := range apps {
		if a.Exposure.AppClient > longest {
			longest = a.Exposure.AppClient
		}
		for _, t := range a.Exposure.ClientTimeouts {
			if t.Client > longest {
				longest = t.Client
			}
		}
	}
	return longest
}

func ruleDoesSomething(r config.PathRule) bool {
	return r.RequireHeader != "" || r.EdgeTokenHeader != "" ||
		r.ClientTimeoutSec > 0 || r.ServerTimeoutSec > 0 || r.RatePer10s > 0
}

func stickTableName(tag string, index int) string {
	name := fmt.Sprintf("st_%s_%d", tag, index)
	if len(name) <= 32 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return "st_" + hex.EncodeToString(sum[:10])
}
