// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"strings"
	"testing"
)

func TestStageD2BackupRestoreDisclosureHasNoFakeAction(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	start := strings.Index(html, `<section class="panel" id="system-backup-restore"`)
	if start < 0 {
		t.Fatal("backup and restore disclosure is missing")
	}
	end := strings.Index(html[start:], `</section>`)
	if end < 0 {
		t.Fatal("backup and restore disclosure is not closed")
	}
	section := html[start : start+end]
	for _, want := range []string{
		"not available in the web panel",
		"sudo easy-waf-backup --dir /var/backups/easy-waf --keep 7",
		"sudo easy-waf-restore /path/to/easy-waf-backup-YYYYMMDD-HHMMSS.tar.gz",
		`href="/help/backup-restore.txt"`,
		"/usr/share/doc/easy-waf/BACKUP_RESTORE.md",
		"Restore replaces the database and appliance state",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("backup and restore disclosure missing %q", want)
		}
	}
	if strings.Contains(section, "<button") || strings.Contains(section, "fetch(") {
		t.Fatal("backup and restore disclosure must not imply an unsupported GUI action")
	}
}

func TestStageD2MobilePrimaryTargetsAndErrorsRemainActionable(t *testing.T) {
	page, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`.nav-toggle, .header-logout, .modal-actions button, .app-content button:not(.secondary) { min-height: var(--touch-target); }`,
		`const ms = k === 'err' ? 0 : (timeoutMs == null ? 5000 : timeoutMs);`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Stage D2 interaction contract missing %q", want)
		}
	}
}
