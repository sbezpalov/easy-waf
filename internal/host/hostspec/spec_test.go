package hostspec

import "testing"

func TestValidToken(t *testing.T) {
	if !ValidToken("abcdef0123456789") {
		t.Fatal("valid")
	}
	if ValidToken("abc") {
		t.Fatal("short")
	}
	if ValidToken("ghijklmnop") {
		t.Fatal("non-hex")
	}
}

func TestClampRollback(t *testing.T) {
	if ClampRollback(0) != RollbackDefaultSec {
		t.Fatal("default")
	}
	if ClampRollback(29) != RollbackMinSec {
		t.Fatal("min")
	}
	if ClampRollback(9999) != RollbackMaxSec {
		t.Fatal("max")
	}
}

func TestDeletableUsername(t *testing.T) {
	if DeletableUsername("root") {
		t.Fatal("root")
	}
	if !DeletableUsername("alice") {
		t.Fatal("alice")
	}
}

func TestValidStagedPath(t *testing.T) {
	if !ValidStagedPath("/var/lib/easy-waf/staging/foo.yaml") {
		t.Fatal("ok")
	}
	if ValidStagedPath("/etc/passwd") {
		t.Fatal("reject")
	}
}

func TestValidateJournalArgs(t *testing.T) {
	if err := ValidateJournalArgs([]string{"--no-pager", "-n", "10", "-u", "haproxy.service"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJournalArgs([]string{"-u", "ssh.service"}); err == nil {
		t.Fatal("ssh not allowed")
	}
	if err := ValidateJournalArgs([]string{"--evil"}); err == nil {
		t.Fatal("unknown flag")
	}
}
