// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSudoers(t *testing.T, main string, dropins map[string]string) {
	t.Helper()
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "sudoers")
	dropDir := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(dropDir, 0o750); err != nil {
		t.Fatal(err)
	}
	main = strings.ReplaceAll(main, "@DIR@", dropDir)
	if err := os.WriteFile(mainPath, []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range dropins {
		if err := os.WriteFile(filepath.Join(dropDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldMain, oldDir := sudoersPath, sudoersDirPath
	sudoersPath, sudoersDirPath = mainPath, dropDir
	t.Cleanup(func() { sudoersPath, sudoersDirPath = oldMain, oldDir })
}

const stockSudoers = "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir @DIR@\n"

func TestPrivilegedAccountReason(t *testing.T) {
	writeGroupFile(t, "root:x:0:\nsudo:x:27:sergey\nadmin:x:118:\ndocker:x:999:builder\nusers:x:100:kiosk,builder,ops\nops:x:1003:\n")

	cases := []struct {
		name    string
		user    string
		gid     string
		dropins map[string]string
		main    string
		want    string // substring of the reason, "" for unprivileged
	}{
		{name: "plain user", user: "kiosk", gid: "100", main: stockSudoers},
		{name: "sudo group", user: "sergey", gid: "1000", main: stockSudoers, want: "privileged group sudo"},
		{name: "docker group", user: "builder", gid: "1001", main: stockSudoers, want: "privileged group docker"},
		{name: "direct sudoers.d grant", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"90-kiosk": "kiosk ALL=(ALL) NOPASSWD: ALL\n"}, want: "named in"},
		{name: "user alias", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"alias": "User_Alias OPS = alice, kiosk\nOPS ALL=(ALL) ALL\n"}, want: "named in"},
		{name: "rule for a local group the user is in", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"users": "%users ALL=(ALL) /usr/bin/apt\n"}, want: "group users"},
		{name: "rule for an LDAP group", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"ldap": "%domain-admins ALL=(ALL) ALL\n"}, want: "cannot be checked"},
		{name: "ALL users", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"all": "ALL ALL=(ALL) ALL\n"}, want: "applies to ALL"},
		{name: "unknown include", user: "kiosk", gid: "100", main: stockSudoers + "#include /etc/sudoers.local\n", want: "does not follow"},
		{name: "ignored dropin names", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"kiosk.bak": "kiosk ALL=(ALL) ALL\n", "kiosk~": "kiosk ALL=(ALL) ALL\n"}},
		{name: "group of others only", user: "kiosk", gid: "100", main: stockSudoers,
			dropins: map[string]string{"ops": "%ops ALL=(ALL) ALL\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeSudoers(t, c.main, c.dropins)
			got, err := privilegedAccountReason(c.user, c.gid)
			if err != nil {
				t.Fatal(err)
			}
			if c.want == "" && got != "" {
				t.Fatalf("unprivileged account refused: %s", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("reason %q, want it to mention %q", got, c.want)
			}
		})
	}
}

// The sudoers file Ubuntu 24.04 ships names %admin, a group that no longer
// exists there; that must not make every account look privileged.
func TestPrivilegedAccountReasonStockUbuntuSudoers(t *testing.T) {
	writeGroupFile(t, "root:x:0:\nsudo:x:27:sergey\nusers:x:100:kiosk\n")
	stock := "Defaults\tenv_reset\nDefaults\tmail_badpass\n" +
		"Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\n" +
		"Defaults\tuse_pty\nroot\tALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n@includedir @DIR@\n"
	writeSudoers(t, stock, map[string]string{"README": "#\n# Files in this directory are parsed by sudo.\n#\n"})
	if got, err := privilegedAccountReason("kiosk", "100"); err != nil || got != "" {
		t.Fatalf("plain user on stock Ubuntu: %q, %v", got, err)
	}
	if got, _ := privilegedAccountReason("sergey", "1000"); !strings.Contains(got, "sudo") {
		t.Fatalf("sudo member on stock Ubuntu: %q", got)
	}
}

func TestPrivilegedAccountReasonNoSudoInstalled(t *testing.T) {
	writeGroupFile(t, "users:x:100:kiosk\n")
	dir := t.TempDir()
	oldMain, oldDir := sudoersPath, sudoersDirPath
	sudoersPath, sudoersDirPath = filepath.Join(dir, "missing"), filepath.Join(dir, "missing.d")
	t.Cleanup(func() { sudoersPath, sudoersDirPath = oldMain, oldDir })
	if got, err := privilegedAccountReason("kiosk", "100"); err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}
