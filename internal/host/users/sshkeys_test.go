package users

import "testing"

func TestValidateSSHPublicKeys_ed25519(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRestOfKeyBase64IsFakeButLongEnoughForTest= comment"
	if err := ValidateSSHPublicKeys([]string{key}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSSHPublicKeys_rejectsShell(t *testing.T) {
	if err := ValidateSSHPublicKeys([]string{"rm -rf"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSSHPublicKeys_rejectsNewline(t *testing.T) {
	if err := ValidateSSHPublicKeys([]string{"ssh-ed25519 AAA=\nrm"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSSHPublicKeys_skipsEmpty(t *testing.T) {
	if err := ValidateSSHPublicKeys([]string{"", "  "}); err != nil {
		t.Fatal(err)
	}
}
