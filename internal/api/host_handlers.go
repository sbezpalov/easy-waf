// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/host/apt"
	"github.com/easy-waf/easy-waf/internal/host/diag"
	"github.com/easy-waf/easy-waf/internal/host/disk"
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/journal"
	"github.com/easy-waf/easy-waf/internal/host/network"
	"github.com/easy-waf/easy-waf/internal/host/nft"
	"github.com/easy-waf/easy-waf/internal/host/rollback"
	"github.com/easy-waf/easy-waf/internal/host/runner"
	hostsystemd "github.com/easy-waf/easy-waf/internal/host/systemd"
	"github.com/easy-waf/easy-waf/internal/host/users"
)

// auditRollbackTokenDigest stores a SHA-256 hex digest of a rollback token in
// audit detail so viewers (and stolen audit exports) cannot finish a commit.
func auditRollbackTokenDigest(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func (s *Server) mountHostRoutes(r chi.Router) {
	r.Route("/host", func(r chi.Router) {
		r.Use(auth.RequireAdmin)

		r.Get("/network", s.hostGetNetwork)
		r.Get("/firewall", s.hostGetFirewall)
		r.Get("/services", s.hostListServices)
		r.Get("/journal", s.hostGetJournal)
		r.Get("/updates", s.hostGetUpdates)
		r.Get("/updates/upgrade/log", s.hostAptUpgradeLog)
		r.Get("/updates/upgrade/status", s.hostAptUpgradeStatus)
		// Read-only observation, like the saved-log GET: admin/XHR apply,
		// but this endpoint cannot start an action and does not need step-up.
		r.Post("/updates/attach/stream", s.hostAptAttachStream)
		r.Get("/updates/autoremove/preview", s.hostAutoremovePreview)
		r.Get("/disk", s.hostDisk)
		r.Get("/users", s.hostListUsers)

		r.Post("/diagnostics/ping", s.hostPing)
		r.Post("/diagnostics/trace", s.hostTrace)

		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStepUp(stepUpWindow))

			// Soft-deprecated immediate apply — use apply + commit instead.
			r.Put("/network/netplan", s.hostPutNetplan)
			r.Post("/network/netplan/apply", s.hostNetplanApply)
			r.Post("/network/netplan/commit", s.hostNetplanCommit)

			r.Put("/firewall/ruleset", s.hostPutFirewall)
			r.Post("/firewall/apply", s.hostApplyFirewall)
			r.Post("/firewall/apply-rollback", s.hostFirewallApplyRB)
			r.Post("/firewall/commit", s.hostFirewallCommit)

			r.Post("/services/{unit}/{action}", s.hostServiceAction)

			r.Post("/updates/update", s.hostAptUpdate)
			r.Post("/updates/upgrade", s.hostAptUpgrade)
			r.Post("/updates/upgrade/stream", s.hostAptUpgradeStream)
			r.Post("/updates/autoremove/stream", s.hostAutoremoveStream)
			r.Post("/updates/clean", s.hostAptClean)

			r.Post("/power/reboot", s.hostReboot)
			r.Post("/power/shutdown", s.hostPoweroff)

			r.Post("/users", s.hostCreateUser)
			r.Delete("/users/{name}", s.hostDeleteUser)
			r.Put("/users/{name}/ssh-keys", s.hostPutSSHKeys)
		})
	})
}

func (s *Server) hostGetNetwork(w http.ResponseWriter, r *http.Request) {
	ov, err := network.GetOverview(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) hostAppendAudit(ctx context.Context, action string, detail map[string]any, warn bool) {
	if s.Eng == nil || s.Eng.Store == nil {
		return
	}
	if warn {
		if detail == nil {
			detail = map[string]any{}
		}
		detail["level"] = "warn"
	}
	_ = s.Eng.Store.AppendAudit(ctx, action, detail)
}

func (s *Server) hostPutNetplan(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusGone, map[string]string{
		"error": "gone: use POST /api/v1/host/network/netplan/apply then /commit",
	})
}

func (s *Server) hostNetplanApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML            string `json:"yaml"`
		RollbackSeconds int    `json:"rollback_seconds"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sec := rollback.ClampRollbackSeconds(body.RollbackSeconds)
	tok, expires, err := network.ApplyNetplanWithRollback(r.Context(), body.YAML, sec)
	if err != nil {
		if errors.Is(err, os.ErrInvalid) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "yaml required"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_netplan_apply", map[string]any{
		"token_sha256":     auditRollbackTokenDigest(tok),
		"rollback_seconds": sec,
		"expires_at":       expires.UTC().Format(time.RFC3339),
	}, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"expires_at": expires.UTC().Format(time.RFC3339),
	})
}

func (s *Server) hostNetplanCommit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if !rollback.ValidToken(body.Token) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token"})
		return
	}
	if err := network.CommitNetplan(r.Context(), body.Token); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_netplan_commit", map[string]any{
		"token_sha256": auditRollbackTokenDigest(body.Token),
	}, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "committed"})
}

func (s *Server) hostGetFirewall(w http.ResponseWriter, r *http.Request) {
	st, err := nft.GetStatus(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hostPutFirewall(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusGone, map[string]string{
		"error": "gone: use POST /api/v1/host/firewall/apply-rollback then /commit",
	})
}

func (s *Server) hostApplyFirewall(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusGone, map[string]string{
		"error": "gone: use POST /api/v1/host/firewall/apply-rollback then /commit",
	})
}

func (s *Server) hostFirewallApplyRB(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ruleset         string `json:"ruleset"`
		RollbackSeconds int    `json:"rollback_seconds"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sec := rollback.ClampRollbackSeconds(body.RollbackSeconds)
	tok, expires, err := nft.ApplyRulesetWithRollback(r.Context(), body.Ruleset, sec)
	if err != nil {
		if errors.Is(err, os.ErrInvalid) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ruleset required"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_firewall_apply", map[string]any{
		"token_sha256":     auditRollbackTokenDigest(tok),
		"rollback_seconds": sec,
		"expires_at":       expires.UTC().Format(time.RFC3339),
	}, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"expires_at": expires.UTC().Format(time.RFC3339),
	})
}

func (s *Server) hostFirewallCommit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if !rollback.ValidToken(body.Token) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token"})
		return
	}
	if err := nft.CommitRuleset(r.Context(), body.Token); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_firewall_commit", map[string]any{
		"token_sha256": auditRollbackTokenDigest(body.Token),
	}, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "committed"})
}

func (s *Server) hostListServices(w http.ResponseWriter, r *http.Request) {
	list, err := hostsystemd.List(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": list})
}

func (s *Server) hostServiceAction(w http.ResponseWriter, r *http.Request) {
	unit := chi.URLParam(r, "unit")
	action := chi.URLParam(r, "action")
	if !strings.HasSuffix(unit, ".service") {
		unit += ".service"
	}
	if !hostsystemd.AllowedUnitAction(unit, action) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unit or action not allowed"})
		return
	}
	if err := hostsystemd.Action(r.Context(), action, unit); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_service_action", map[string]any{"unit": unit, "action": action}, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "unit": unit, "action": action})
}

func (s *Server) hostGetJournal(w http.ResponseWriter, r *http.Request) {
	q := journal.Query{
		Unit:     r.URL.Query().Get("unit"),
		Since:    r.URL.Query().Get("since"),
		Until:    r.URL.Query().Get("until"),
		Priority: r.URL.Query().Get("priority"),
	}
	if n := r.URL.Query().Get("lines"); n != "" {
		if lines, err := strconv.Atoi(n); err == nil {
			q.Lines = lines
		}
	}
	out, err := journal.Read(r.Context(), q)
	if err != nil {
		// Validation failures are stable short strings; broker/journalctl
		// detail must not reach the UI.
		if strings.Contains(err.Error(), "unit") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") {
			writeClientError(w, http.StatusBadRequest, err.Error(), nil)
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"log": out})
}

func (s *Server) hostGetUpdates(w http.ResponseWriter, r *http.Request) {
	st, err := apt.ListUpgradable(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hostDisk(w http.ResponseWriter, r *http.Request) {
	mounts, err := disk.Usage("/", "/var")
	if err != nil {
		writeInternalError(w, err)
		return
	}
	resp := map[string]any{"mounts": mounts}
	if n, err := apt.CacheSizeBytes(r.Context()); err == nil && n >= 0 {
		resp["cache_bytes"] = n
	}
	if st, err := apt.AutoremovePreview(r.Context()); err == nil {
		if c := len(st.Packages); c > 0 {
			resp["removable_count"] = c
		} else if !apt.AutoremoveNothingToDo(st) {
			resp["removable_count"] = 0
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) hostAptClean(w http.ResponseWriter, r *http.Request) {
	before, err := apt.CacheSizeBytes(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := apt.CleanCache(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	after, err := apt.CacheSizeBytes(r.Context())
	if err != nil {
		after = 0
	}
	freed := before - after
	if freed < 0 {
		freed = 0
	}
	s.hostAppendAudit(r.Context(), "host_apt_clean", map[string]any{
		"freed_bytes": freed,
		"before":      before,
		"after":       after,
	}, false)
	writeJSON(w, http.StatusOK, map[string]int64{"freed_bytes": freed})
}

func (s *Server) hostAptUpdate(w http.ResponseWriter, r *http.Request) {
	st, err := apt.Update(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	s.hostAppendAudit(r.Context(), "host_apt_update", nil, false)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hostAptUpgrade(w http.ResponseWriter, r *http.Request) {
	st, err := apt.Upgrade(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	s.hostAppendAudit(r.Context(), "host_apt_upgrade", nil, true)
	writeJSON(w, http.StatusOK, st)
}

var privilegedStreamFn = runner.PrivilegedStream

func (s *Server) hostAptAttachStream(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	ids := query["run_id"]
	if err != nil || len(ids) != 1 || len(ids[0]) != 32 || !hostspec.ValidToken(ids[0]) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one valid APT run_id is required"})
		return
	}
	s.streamAptAction(w, r, "apt-action-attach-stream", "host_apt_attach", "host_apt_attach_done", ids[0])
}

func (s *Server) hostAptUpgradeStream(w http.ResponseWriter, r *http.Request) {
	s.streamAptAction(w, r, "apt-upgrade-stream", "host_apt_upgrade", "host_apt_upgrade_done")
}

func (s *Server) hostAutoremoveStream(w http.ResponseWriter, r *http.Request) {
	s.streamAptAction(w, r, "apt-autoremove-stream", "host_apt_autoremove", "host_apt_autoremove_done")
}

func (s *Server) hostAutoremovePreview(w http.ResponseWriter, r *http.Request) {
	st, err := apt.AutoremovePreview(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

const aptHTTPWriteTimeout = 5 * time.Second

func (s *Server) streamAptAction(w http.ResponseWriter, r *http.Request, brokerOp, auditEvent, auditDoneEvent string, brokerArgs ...string) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	// chi's logging wrapper implements Flush without returning the underlying
	// FlushError. Writes still pass through it for logging; unwrap only this
	// known non-buffering wrapper for error-aware flushes.
	flushTarget := w
	for {
		wrapped, ok := flushTarget.(middleware.WrapResponseWriter)
		if !ok {
			break
		}
		flushTarget = wrapped.Unwrap()
	}
	flushController := http.NewResponseController(flushTarget)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Content-Encoding", "identity")

	detail := map[string]any{"stream": true}
	if brokerOp == "apt-action-attach-stream" && len(brokerArgs) == 1 {
		detail["run_id"] = brokerArgs[0]
	}
	s.hostAppendAudit(r.Context(), auditEvent, detail, false)
	argv := append([]string{brokerOp}, brokerArgs...)

	exitCode := -1
	exitSeen := false
	clientFailed := false
	writeLine := func(line []byte) error {
		// Bound each delivery, not the interval between events: an HTTP/2
		// write deadline left armed while idle can terminate a healthy stream.
		err := rc.SetWriteDeadline(time.Now().Add(aptHTTPWriteTimeout))
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			clientFailed = true
			return err
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			clientFailed = true
			return err
		}
		if err := flushController.Flush(); err != nil {
			clientFailed = true
			return err
		}
		err = rc.SetWriteDeadline(time.Time{})
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			clientFailed = true
			return err
		}
		return nil
	}

	err := privilegedStreamFn(r.Context(), func(line []byte) error {
		if err := writeLine(line); err != nil {
			return err
		}
		var ev struct {
			Type  string `json:"type"`
			Code  *int   `json:"code"`
			Error string `json:"error"`
		}
		if json.Unmarshal(line, &ev) == nil && ev.Type == "exit" && ev.Code != nil && (*ev.Code != 0 || ev.Error == "") {
			exitCode = *ev.Code
			exitSeen = true
		}
		return nil
	}, argv...)
	if err == nil && !exitSeen {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		// Client may have disconnected; broker still runs apt — do not claim the action stopped.
		if !clientFailed {
			b, _ := json.Marshal(map[string]any{"type": "exit", "code": -1, "error": err.Error()})
			_ = writeLine(b)
		}
		return
	}

	detail["exit_code"] = exitCode
	s.hostAppendAudit(r.Context(), auditDoneEvent, detail, exitCode != 0)
}

func (s *Server) hostAptUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	out, err := runner.Privileged(r.Context(), "apt-upgrade-status")
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var st map[string]any
	if len(out) > 0 {
		_ = json.Unmarshal(out, &st)
	}
	if st == nil {
		st = map[string]any{"active": false}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hostReboot(w http.ResponseWriter, r *http.Request) {
	if err := hostPower(r.Context(), "reboot"); err != nil {
		writeInternalError(w, err)
		return
	}
	s.hostAppendAudit(r.Context(), "host_power_reboot", nil, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "rebooting"})
}

func (s *Server) hostPoweroff(w http.ResponseWriter, r *http.Request) {
	if err := hostPower(r.Context(), "poweroff"); err != nil {
		writeInternalError(w, err)
		return
	}
	s.hostAppendAudit(r.Context(), "host_power_shutdown", nil, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "shutting_down"})
}

func hostPower(ctx context.Context, action string) error {
	_, err := runner.Privileged(ctx, action)
	return err
}

func (s *Server) hostListUsers(w http.ResponseWriter, _ *http.Request) {
	list, err := users.List()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": list})
}

func (s *Server) hostCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if !hostspec.ValidUsername(body.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid username"})
		return
	}
	if err := users.CreateUser(r.Context(), body.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_user_create", map[string]any{"username": body.Username}, false)
	writeJSON(w, http.StatusCreated, map[string]string{"username": body.Username})
}

func (s *Server) hostDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !hostspec.DeletableUsername(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user cannot be deleted"})
		return
	}
	if err := users.DeleteUser(r.Context(), name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_user_delete", map[string]any{"username": name}, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) hostPutSSHKeys(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !hostspec.ManageableUsername(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user is protected or invalid"})
		return
	}
	var body struct {
		Keys []string `json:"keys"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := users.SetSSHKeys(r.Context(), name, body.Keys); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.hostAppendAudit(r.Context(), "host_user_ssh_keys", map[string]any{
		"username": name,
		"count":    len(body.Keys),
	}, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) hostPing(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host  string `json:"host"`
		Count int    `json:"count"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	out, err := diag.Ping(r.Context(), body.Host, body.Count)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"output": out})
}

func (s *Server) hostTrace(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
	}
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	out, err := diag.Trace(r.Context(), body.Host)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"output": out})
}
