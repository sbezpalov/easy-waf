// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type backupServiceStatus struct {
	State      string     `json:"state"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (s *Server) hostBackupStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,Result,ExecMainExitTimestamp", "easy-waf-backup.service")
	cmd.Env = append(cmd.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err := cmd.Output()
	status := backupServiceStatus{State: "unavailable"}
	if err == nil {
		status = parseBackupServiceStatus(string(out))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, status)
}

func parseBackupServiceStatus(output string) backupServiceStatus {
	props := make(map[string]string)
	for line := range strings.SplitSeq(output, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			props[key] = strings.TrimSpace(value)
		}
	}
	status := backupServiceStatus{State: "unavailable"}
	if props["LoadState"] != "loaded" {
		return status
	}
	switch props["ActiveState"] {
	case "activating":
		status.State = "running"
		return status
	case "failed":
		status.State = "failed"
	case "inactive":
	default:
		return status
	}
	at, err := time.Parse("Mon 2006-01-02 15:04:05 UTC", props["ExecMainExitTimestamp"])
	if err == nil {
		status.FinishedAt = &at
	}
	if status.State == "failed" {
		return status
	}
	if status.FinishedAt != nil && props["Result"] == "success" {
		status.State = "succeeded"
	}
	return status
}
