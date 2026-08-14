package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/enroll"
	"golang.org/x/crypto/bcrypt"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestEnrollmentFreshInstallRestartAndConsume(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	n, err := st.CountUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		t.Skip("enrollment empty-users tests skipped: DATABASE_URL already has users (refusing to wipe)")
	}

	dir := t.TempDir()
	t.Cleanup(func() {
		_, _ = st.db.ExecContext(context.Background(), `DELETE FROM users WHERE username = $1`, "operator")
		_, _ = st.db.ExecContext(context.Background(), `DELETE FROM operator_enrollment`)
	})
	created, path, err := st.EnsureOperatorEnrollment(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created || path == "" {
		t.Fatalf("expected new enrollment file, created=%v path=%q", created, path)
	}
	stInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stInfo.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", stInfo.Mode().Perm())
	}
	secret, err := enroll.ReadFile(dir)
	if err != nil {
		t.Fatal(err)
	}

	created2, path2, err := st.EnsureOperatorEnrollment(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("restart must not rotate a matching pending secret")
	}
	if path2 != path {
		t.Fatalf("path changed %s -> %s", path, path2)
	}
	secret2, err := enroll.ReadFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if secret2 != secret {
		t.Fatal("restart rotated the enrollment secret")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeEnrollmentAndCreateUser(ctx, secret, "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	if err := enroll.RemoveFile(dir); err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeEnrollmentAndCreateUser(ctx, secret, "operator2", string(hash)); err != ErrEnrollmentAlreadyCompleted {
		t.Fatalf("reuse: %v", err)
	}

	u, err := st.GetUserByUsername(ctx, "operator")
	if err != nil || u == nil {
		t.Fatalf("user: %v %#v", err, u)
	}
	oldHash := u.PasswordHash
	created3, _, err := st.EnsureOperatorEnrollment(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if created3 {
		t.Fatal("existing users must not be reset")
	}
	u2, err := st.GetUserByUsername(ctx, "operator")
	if err != nil || u2 == nil || u2.PasswordHash != oldHash {
		t.Fatal("existing operator password must be unchanged")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "enrollment")); !os.IsNotExist(err) {
		t.Fatal("enrollment file must be removed when users exist")
	}
}

func TestPasswordChangeIncrementsSessionVersion(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	user := "ew-test-sv-" + time.Now().UTC().Format("150405.000")
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	u := &config.AdminUser{Username: user, PasswordHash: string(hash), SessionVersion: 1}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.db.ExecContext(context.Background(), `DELETE FROM users WHERE username = $1`, user)
	})

	got, err := st.GetUserByUsername(ctx, user)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.SessionVersion != 1 {
		t.Fatalf("sv=%d", got.SessionVersion)
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte("new-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUserPassword(ctx, got.ID, string(newHash), false); err != nil {
		t.Fatal(err)
	}
	got2, err := st.GetUserByUsername(ctx, user)
	if err != nil || got2 == nil {
		t.Fatal(err)
	}
	if got2.SessionVersion != 2 {
		t.Fatalf("expected session_version 2, got %d", got2.SessionVersion)
	}
}
