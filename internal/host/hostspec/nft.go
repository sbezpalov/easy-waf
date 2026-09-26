// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"errors"
	"fmt"
)

// ValidateNftRuleset rejects an easy-waf nftables ruleset that uses include.
//
// easy-waf-hostd runs `nft -c -f` on this file as root and returns nft's
// stderr to the API. nft reads an included file as root and echoes the lines
// it cannot parse, so `include "/etc/shadow"` would hand any root-readable
// file to whoever controls the API. The managed ruleset never needs include:
// /etc/nftables.conf includes it, not the other way round.
//
// The keyword is looked for outside comments and double-quoted strings, the
// only places nft lets it appear as text.
func ValidateNftRuleset(b []byte) error {
	inString, inComment := false, false
	word := make([]byte, 0, 16)
	flush := func() error {
		defer func() { word = word[:0] }()
		if string(word) == "include" {
			return errors.New("nftables ruleset must not use include")
		}
		return nil
	}
	for i, c := range b {
		if c == 0 {
			return fmt.Errorf("nftables ruleset contains a NUL byte at offset %d", i)
		}
		switch {
		case inComment:
			if c == '\n' {
				inComment = false
			}
			continue
		case inString:
			if c == '"' {
				inString = false
			}
			continue
		}
		if isWordByte(c) {
			word = append(word, c)
			continue
		}
		if err := flush(); err != nil {
			return err
		}
		switch c {
		case '#':
			inComment = true
		case '"':
			inString = true
		}
	}
	return flush()
}

func isWordByte(c byte) bool {
	return c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
