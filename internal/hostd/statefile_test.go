package hostd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The state directory is owned by the unprivileged easy-waf account, so every
// one of these cases is something a compromised easy-waf-api can actually set
// up. Each was a working primitive against the broker before these tests.

func newTestStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	restore := SetStateDirForTest(dir)
	t.Cleanup(restore)
	return dir
}

// secretOutside stands in for /etc/shadow: a root-owned file the broker must
// never read or truncate on the caller's behalf.
func secretOutside(t *testing.T) (dir, file string) {
	t.Helper()
	dir = t.TempDir()
	file = filepath.Join(dir, "shadow")
	if err := os.WriteFile(file, []byte("root:$6$hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

func TestStateOpenFileRefusesSymlinkedFile(t *testing.T) {
	state := newTestStateDir(t)
	_, secret := secretOutside(t)

	if err := os.MkdirAll(filepath.Join(state, "rollback"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(state, "rollback", "nft-deadbeef.bak")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// Control: the setup really is a working primitive. If this ever stops
	// reading the secret, the test below proves nothing and needs rewriting.
	if b, err := os.ReadFile(link); err != nil || !strings.Contains(string(b), "root:") {
		t.Fatalf("test setup does not reproduce the primitive: %v", err)
	}

	if f, err := stateOpenFile(link); err == nil {
		b := make([]byte, 64)
		n, _ := f.Read(b)
		_ = f.Close()
		t.Fatalf("opened a symlinked backup and read %q", b[:n])
	}
}

func TestStateOpenFileRefusesSymlinkedDirectory(t *testing.T) {
	state := newTestStateDir(t)
	outside, _ := secretOutside(t)

	// `rm -rf staging && ln -s /etc staging` — the case RESOLVE_BENEATH alone
	// does not cover, because the escape happens while opening the anchor.
	if err := os.Symlink(outside, filepath.Join(state, "staging")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if f, err := stateOpenFile(filepath.Join(state, "staging", "shadow")); err == nil {
		_ = f.Close()
		t.Fatal("opened a file through a symlinked directory")
	}
}

func TestStateCreateFileRefusesSymlinkAndDoesNotTruncate(t *testing.T) {
	state := newTestStateDir(t)
	_, secret := secretOutside(t)

	link := filepath.Join(state, "apt-action.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if f, err := stateCreateFile(link, 0o640); err == nil {
		_ = f.Close()
		t.Fatal("created through a symlink")
	}
	// The whole point: the target must still be intact.
	b, err := os.ReadFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("symlink target was truncated")
	}
}

func TestStateWriteFileRefusesSymlinkedDirectory(t *testing.T) {
	state := newTestStateDir(t)
	outside, _ := secretOutside(t)

	if err := os.Symlink(outside, filepath.Join(state, "rollback")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := stateWriteFile(filepath.Join(state, "rollback", "nft-deadbeef.bak"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("wrote into a symlinked directory")
	}
	if _, statErr := os.Stat(filepath.Join(outside, "nft-deadbeef.bak")); statErr == nil {
		t.Fatal("file landed outside the state directory")
	}
}

func TestStateRemoveFileRemovesTheLinkNotTheTarget(t *testing.T) {
	state := newTestStateDir(t)
	_, secret := secretOutside(t)

	link := filepath.Join(state, "rollback", "nft-deadbeef.bak")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := stateRemoveFile(link); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("symlink was not removed")
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("target was removed instead of the link: %v", err)
	}
}

func TestStateRelRejectsPathsOutside(t *testing.T) {
	newTestStateDir(t)
	for _, p := range []string{
		"/etc/shadow",
		"/var/lib/easy-waf-other/x",
		filepath.Join(stateDir, ".."),
		filepath.Join(stateDir, "..", "elsewhere"),
		stateDir,
	} {
		if rel, err := stateRel(p); err == nil {
			t.Errorf("stateRel(%q) accepted, returned %q", p, rel)
		}
	}
	if rel, err := stateRel(filepath.Join(stateDir, "rollback", "a.bak")); err != nil {
		t.Errorf("stateRel rejected a legitimate path: %v", err)
	} else if rel != filepath.Join("rollback", "a.bak") {
		t.Errorf("stateRel = %q", rel)
	}
}

func TestStateRoundTrip(t *testing.T) {
	state := newTestStateDir(t)
	path := filepath.Join(state, "rollback", "nft-abcdef01.bak")

	if _, exists, err := stateFileSize(path); err != nil || exists {
		t.Fatalf("size before write: exists=%v err=%v", exists, err)
	}
	want := strings.Repeat("table inet easy_waf { }\n", 10)
	if err := stateWriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	size, exists, err := stateFileSize(path)
	if err != nil || !exists || size != int64(len(want)) {
		t.Fatalf("size after write: %d exists=%v err=%v", size, exists, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	f, err := stateOpenFile(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := f.Read(got); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if string(got) != want {
		t.Errorf("content mismatch")
	}
	if err := stateRemoveFile(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, exists, _ := stateFileSize(path); exists {
		t.Error("file still present after remove")
	}
	// No leftover temp file from the atomic write.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("unexpected leftover %q", e.Name())
	}
}

func TestRollbackBackupRoundTripAndSymlinkRefusal(t *testing.T) {
	state := newTestStateDir(t)
	_, secret := secretOutside(t)

	src := filepath.Join(t.TempDir(), "easy-waf.nft")
	if err := os.WriteFile(src, []byte("flush ruleset\ntable inet t { }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(state, "rollback", "nft-abcdef01.bak")

	if err := saveRollbackBackup(src, bak, 0o644); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, ok, err := readRollbackBackup(bak)
	if err != nil || !ok || string(data) != "flush ruleset\ntable inet t { }\n" {
		t.Fatalf("read back: ok=%v err=%v data=%q", ok, err, data)
	}

	// A missing source is recorded as an empty backup, which is what makes the
	// revert flush the ruleset instead of leaving the new rules live.
	empty := filepath.Join(state, "rollback", "nft-abcdef02.bak")
	if err := saveRollbackBackup(filepath.Join(t.TempDir(), "absent"), empty, 0o644); err != nil {
		t.Fatalf("save absent: %v", err)
	}
	data, ok, err = readRollbackBackup(empty)
	if err != nil || !ok || len(data) != 0 {
		t.Fatalf("empty backup: ok=%v err=%v len=%d", ok, err, len(data))
	}

	// And the primitive itself: a backup replaced by a symlink must not be read.
	poisoned := filepath.Join(state, "rollback", "nft-abcdef03.bak")
	if err := os.Symlink(secret, poisoned); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if data, ok, err := readRollbackBackup(poisoned); err == nil && ok {
		t.Fatalf("read through a symlinked backup: %q", data)
	}
}
