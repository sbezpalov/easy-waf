package auth

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/easy-waf/easy-waf/internal/store"
)

// Session validates Authorization: Bearer — JWT (HS256) or legacy EASY_WAF_ADMIN_TOKEN.
// On success, attaches Principal to the request context.
func Session(st *store.Store, jwtSecret []byte) func(http.Handler) http.Handler {
	legacyTok := strings.TrimSpace(os.Getenv("EASY_WAF_ADMIN_TOKEN"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			raw = strings.TrimSpace(raw)
			if raw == "" {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if legacyTok != "" && len(raw) == len(legacyTok) && subtle.ConstantTimeCompare([]byte(raw), []byte(legacyTok)) == 1 {
				p := &Principal{Username: "automation", IsLegacyToken: true}
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
				return
			}
			claims, err := ParseJWT(jwtSecret, raw)
			if err != nil {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			u, err := st.GetUserByUsername(r.Context(), claims.Subject)
			if err != nil || u == nil {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !SessionMatches(claims.SessionVersion, u.SessionVersion) {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			p := &Principal{
				Username:           u.Username,
				MustChangePassword: u.MustChangePassword,
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// PasswordChangeGate returns 403 until the user changes the initial password (not applied to legacy tokens).
func PasswordChangeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if p.IsLegacyToken || !p.MustChangePassword {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if path == "/api/v1/auth/me" || path == "/api/v1/auth/change-password" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"password_change_required","must_change_password":true}` + "\n"))
	})
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}` + "\n"))
}
