package api

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/easy-waf/easy-waf/internal/diagnostics"
)

func (s *Server) postDiagnosticsBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("easy-waf-diag-api-%s.tar.gz", stamp)

	b, err := diagnostics.BuildSupportBundleGzip(r.Context(), diagnostics.Params{
		StateDir: s.Eng.StateDir,
		EnvPath:  "/etc/easy-waf/easy-waf.env",
		Store:    s.Eng.Store,
		Settings: s.Eng.Settings,
		Version:  os.Getenv("EASY_WAF_VERSION"),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
