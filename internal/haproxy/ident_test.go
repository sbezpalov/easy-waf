package haproxy

import "testing"

// Application IDs are validated as [A-Za-z0-9_-]+ (config.ValidateResourceID), so
// the ACL tag derived from them must be injective over that charset. It was not:
// '-' and '_' both collapsed to '_', letting two applications share one ACL name.
// HAProxy ORs same-named ACLs, so each application's security rules also matched
// the other application's host.
func TestSanitizeAppACLTag_distinguishesDashAndUnderscore(t *testing.T) {
	dash := sanitizeAppACLTag("pay-api", "pay.example.com")
	underscore := sanitizeAppACLTag("pay_api", "pay2.example.com")
	if dash == underscore {
		t.Fatalf("ACL tags collide: %q for both pay-api and pay_api", dash)
	}
	if dash != "pay-api" || underscore != "pay_api" {
		t.Fatalf("unexpected tags: %q / %q", dash, underscore)
	}
}

func TestSanitizeAppACLTag_hostFallbackStaysDistinct(t *testing.T) {
	dotted := sanitizeAppACLTag("", "a.b.com")
	dashed := sanitizeAppACLTag("", "a-b.com")
	if dotted == dashed {
		t.Fatalf("host-derived tags collide: %q", dotted)
	}
}

func TestSanitizeAppACLTag_rejectsUnsafeRunes(t *testing.T) {
	got := sanitizeAppACLTag("bad name\nacl x", "h")
	for _, r := range got {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			t.Fatalf("tag %q contains unsafe rune %q", got, r)
		}
	}
}

func TestSanitizeAppACLTag_emptyFallback(t *testing.T) {
	if got := sanitizeAppACLTag("", ""); got != "app" {
		t.Fatalf("empty id/host: got %q, want app", got)
	}
	if got := sanitizeAppACLTag("___", ""); got != "app" {
		t.Fatalf("separator-only id: got %q, want app", got)
	}
}

func TestSanitizeBackendName_distinguishesDashAndDot(t *testing.T) {
	if sanitizeBackendName("a-b.com") == sanitizeBackendName("a.b.com") {
		t.Fatal("backend names collide for a-b.com and a.b.com")
	}
	if got := sanitizeBackendName("shop.example.com"); got != "bk_shop_example_com" {
		t.Fatalf("unexpected backend name: %q", got)
	}
}
