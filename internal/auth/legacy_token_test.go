package auth

import (
	"strings"
	"testing"
)

func TestLoadLegacyToken_rejectsShortToken(t *testing.T) {
	t.Setenv("EASY_WAF_ADMIN_TOKEN", "admin123")
	tok := loadLegacyToken()
	if tok.enabled {
		t.Fatal("a token below MinLegacyTokenLen must be ignored, not accepted")
	}
	if tok.matches("admin123") {
		t.Fatal("rejected token still authenticates")
	}
}

func TestLoadLegacyToken_unset(t *testing.T) {
	t.Setenv("EASY_WAF_ADMIN_TOKEN", "")
	tok := loadLegacyToken()
	if tok.enabled || tok.matches("") {
		t.Fatal("unset token must not authenticate")
	}
}

func TestLegacyToken_matches(t *testing.T) {
	secret := strings.Repeat("a", MinLegacyTokenLen)
	t.Setenv("EASY_WAF_ADMIN_TOKEN", "  "+secret+"  ")
	tok := loadLegacyToken()
	if !tok.enabled {
		t.Fatal("valid token not enabled")
	}
	if !tok.matches(secret) {
		t.Fatal("valid token rejected")
	}
	for _, wrong := range []string{
		"",
		secret + "x",
		secret[:len(secret)-1],
		strings.Repeat("b", MinLegacyTokenLen),
	} {
		if tok.matches(wrong) {
			t.Fatalf("wrong value accepted: %q", wrong)
		}
	}
}

// The comparison must not branch on length: a wrong value of a different length
// has to travel the same path as one of equal length.
func TestLegacyToken_comparesFixedWidthDigest(t *testing.T) {
	secret := strings.Repeat("z", 40)
	t.Setenv("EASY_WAF_ADMIN_TOKEN", secret)
	tok := loadLegacyToken()
	if tok.matches("z") || tok.matches(strings.Repeat("z", 200)) {
		t.Fatal("length-mismatched value accepted")
	}
	if len(tok.digest) != 32 {
		t.Fatalf("digest width = %d, want 32", len(tok.digest))
	}
}
