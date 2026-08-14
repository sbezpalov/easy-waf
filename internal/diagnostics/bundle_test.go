package diagnostics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSupportBundleGzip_nilStore(t *testing.T) {
	_, err := BuildSupportBundleGzip(context.Background(), Params{})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestManagedHAProxyConfigPath(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.WriteFile(inside, []byte("global\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := managedHAProxyConfigPath(stateDir, inside)
	want, resolveErr := filepath.EvalSymlinks(inside)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if err != nil || got != want {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, "/etc/passwd"); err == nil {
		t.Fatal("expected path outside state directory to fail")
	}
}

func TestManagedHAProxyConfigPathRejectsEscapingSymlink(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, link); err == nil {
		t.Fatal("expected escaping symlink to fail")
	}
}
