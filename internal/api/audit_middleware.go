package api

import (
	"net/http"
	"strings"
)

type statusCapture struct {
	http.ResponseWriter
	code int
}

func (s *statusCapture) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

// auditHTTPMutations logs each mutating HTTP request (method + path) with status and a coarse category.
// Does not store request bodies. Runs after the handler (captures HTTP status).
func (s *Server) auditHTTPMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusCapture{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		detail := map[string]any{
			"http_status": sw.code,
			"category":    auditHTTPRouteCategory(r.URL.Path),
		}
		action := r.Method + " " + r.URL.Path
		_ = s.Eng.Store.AppendAudit(r.Context(), action, detail)
	})
}

func auditHTTPRouteCategory(path string) string {
	switch {
	case strings.HasSuffix(path, "/apply"):
		return "apply"
	case strings.Contains(path, "/revisions/") && strings.Contains(path, "/rollback"):
		return "rollback"
	case strings.Contains(path, "/applications"):
		return "applications"
	case strings.Contains(path, "/security/modes"):
		return "security-modes"
	case strings.Contains(path, "/certificates"):
		return "certificates"
	case strings.Contains(path, "/settings"):
		return "settings"
	case strings.Contains(path, "/ipbl/"):
		return "ipbl"
	case strings.Contains(path, "/ipwl/"):
		return "ipwl"
	case strings.Contains(path, "/blocked-ua"):
		return "blocked-ua"
	case strings.Contains(path, "/integrations/crowdsec"):
		return "crowdsec"
	case strings.Contains(path, "/auth/change-password"):
		return "auth"
	default:
		return "other"
	}
}
