package admin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/disk"
	"github.com/easy-waf/easy-waf/internal/store"
)

// CheckStatus represents the outcome of a diagnostic check.
type CheckStatus string

const (
	StatusOK   CheckStatus = "OK"
	StatusWarn CheckStatus = "WARN"
	StatusFail CheckStatus = "FAIL"
)

// CheckResult holds the details of a single diagnostic check.
type CheckResult struct {
	Category string      `json:"category"`
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Message  string      `json:"message"`
	Details  string      `json:"details,omitempty"`
}

// DoctorReport contains all check results and overall summary.
type DoctorReport struct {
	Timestamp time.Time     `json:"timestamp"`
	Summary   string        `json:"summary"`
	Checks    []CheckResult `json:"checks"`
	Passed    int           `json:"passed"`
	Warnings  int           `json:"warnings"`
	Failed    int           `json:"failed"`
}

// DoctorOptions provides parameters for the diagnostic run.
type DoctorOptions struct {
	StateDir    string
	DatabaseURL string
	EnvFile     string
}

// RunDoctor performs all diagnostic checks on the appliance.
func RunDoctor(ctx context.Context, opts DoctorOptions) DoctorReport {
	stateDir := strings.TrimSpace(opts.StateDir)
	if stateDir == "" {
		stateDir = "/var/lib/easy-waf"
	}
	envFile := strings.TrimSpace(opts.EnvFile)
	if envFile == "" {
		envFile = "/etc/easy-waf/easy-waf.env"
	}
	dbURL := strings.TrimSpace(opts.DatabaseURL)
	if dbURL == "" {
		if v, err := ReadEnvKey(envFile, "DATABASE_URL"); err == nil && strings.TrimSpace(v) != "" {
			dbURL = strings.TrimSpace(v)
		} else if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); v != "" {
			dbURL = v
		}
	}

	report := DoctorReport{
		Timestamp: time.Now().UTC(),
		Checks:    make([]CheckResult, 0, 16),
	}

	// 1. Filesystem & State Directory
	report.addChecks(checkStateDir(stateDir))
	report.addChecks(checkDiskSpace(stateDir))

	// 2. Database Checks
	report.addChecks(checkDatabase(ctx, dbURL))

	// 3. HAProxy Edge Checks
	report.addChecks(checkHAProxy(stateDir))

	// 4. System Services Checks
	report.addChecks(checkServices(ctx))

	// 5. GeoIP Database Checks
	report.addChecks(checkGeoIP(stateDir))

	// 6. Certificates Checks
	report.addChecks(checkCertificates(stateDir))

	for _, c := range report.Checks {
		switch c.Status {
		case StatusOK:
			report.Passed++
		case StatusWarn:
			report.Warnings++
		case StatusFail:
			report.Failed++
		}
	}

	switch {
	case report.Failed > 0:
		report.Summary = fmt.Sprintf("FAIL (%d errors, %d warnings, %d passed)", report.Failed, report.Warnings, report.Passed)
	case report.Warnings > 0:
		report.Summary = fmt.Sprintf("WARN (%d warnings, %d passed)", report.Warnings, report.Passed)
	default:
		report.Summary = fmt.Sprintf("OK (all %d checks passed)", report.Passed)
	}

	return report
}

func (r *DoctorReport) addChecks(results []CheckResult) {
	r.Checks = append(r.Checks, results...)
}

func checkStateDir(stateDir string) []CheckResult {
	var checks []CheckResult

	st, err := os.Stat(stateDir)
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "State Directory",
			Status:   StatusFail,
			Message:  fmt.Sprintf("Directory %s does not exist or is unreadable: %v", stateDir, err),
		})
		return checks
	}

	perm := st.Mode().Perm()
	if perm&0o007 != 0 {
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "State Directory Permissions",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("Permissions %04o on %s are world-accessible (recommended: 0750)", perm, stateDir),
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "State Directory",
			Status:   StatusOK,
			Message:  fmt.Sprintf("Directory %s exists with secure permissions (%04o)", stateDir, perm),
		})
	}

	// Check secrets dir
	secDir := filepath.Join(stateDir, "secrets")
	if sst, err := os.Stat(secDir); err == nil {
		sperm := sst.Mode().Perm()
		if sperm&0o077 != 0 {
			checks = append(checks, CheckResult{
				Category: "Storage",
				Name:     "Secrets Directory Permissions",
				Status:   StatusWarn,
				Message:  fmt.Sprintf("Permissions %04o on %s are group/world-accessible (recommended: 0700)", sperm, secDir),
			})
		} else {
			checks = append(checks, CheckResult{
				Category: "Storage",
				Name:     "Secrets Directory",
				Status:   StatusOK,
				Message:  fmt.Sprintf("Directory %s exists with restricted permissions (%04o)", secDir, sperm),
			})
		}
	}

	return checks
}

func checkDiskSpace(stateDir string) []CheckResult {
	var checks []CheckResult
	mounts, err := disk.Usage(stateDir)
	if err != nil || len(mounts) == 0 {
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "Disk Usage",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("Unable to inspect disk space for %s: %v", stateDir, err),
		})
		return checks
	}

	m := mounts[0]
	switch {
	case m.UsedPercent >= 90:
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "Disk Usage",
			Status:   StatusFail,
			Message:  fmt.Sprintf("Disk usage is critical: %d%% used (free: %s)", m.UsedPercent, formatBytes(m.FreeBytes)),
		})
	case m.UsedPercent >= 80:
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "Disk Usage",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("Disk usage is elevated: %d%% used (free: %s)", m.UsedPercent, formatBytes(m.FreeBytes)),
		})
	default:
		checks = append(checks, CheckResult{
			Category: "Storage",
			Name:     "Disk Usage",
			Status:   StatusOK,
			Message:  fmt.Sprintf("%d%% used (free: %s of %s)", m.UsedPercent, formatBytes(m.FreeBytes), formatBytes(m.TotalBytes)),
		})
	}

	return checks
}

func checkDatabase(ctx context.Context, dsn string) []CheckResult {
	var checks []CheckResult
	if dsn == "" {
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "PostgreSQL Connection",
			Status:   StatusFail,
			Message:  "DATABASE_URL is not configured (check easy-waf.env or environment)",
		})
		return checks
	}

	st, err := store.OpenPostgresForDiagnostics(dsn)
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "PostgreSQL Connection",
			Status:   StatusFail,
			Message:  fmt.Sprintf("Failed to connect to PostgreSQL: %v", err),
		})
		return checks
	}
	defer st.Close()

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := st.Ping(ctxTimeout); err != nil {
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "PostgreSQL Ping",
			Status:   StatusFail,
			Message:  fmt.Sprintf("Ping failed: %v", err),
		})
		return checks
	}

	checks = append(checks, CheckResult{
		Category: "Database",
		Name:     "PostgreSQL Connection",
		Status:   StatusOK,
		Message:  "Database connected and responsive",
	})

	tx, err := st.BeginReadOnly(ctxTimeout)
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "Read-only Diagnostics",
			Status:   StatusFail,
			Message:  fmt.Sprintf("Could not start read-only diagnostics: %v", err),
		})
		return checks
	}
	defer func() { _ = tx.Rollback() }()

	// The repository intentionally has no migration ledger. Verify the security-critical
	// schema objects introduced by migrations 016-018 instead of querying a fictitious table.
	var hasSessionVersion, hasEnrollment, hasTLSVerify, hasTLSCA, hasTLSServerName bool
	err = tx.QueryRowContext(ctxTimeout, `
		SELECT
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'session_version'),
			to_regclass(current_schema() || '.operator_enrollment') IS NOT NULL,
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'applications' AND column_name = 'backend_tls_verify'),
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'applications' AND column_name = 'backend_tls_ca_file'),
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'applications' AND column_name = 'backend_tls_server_name')`).
		Scan(&hasSessionVersion, &hasEnrollment, &hasTLSVerify, &hasTLSCA, &hasTLSServerName)
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "Security Schema",
			Status:   StatusFail,
			Message:  fmt.Sprintf("Could not verify security schema: %v", err),
		})
		return checks
	}
	missing := make([]string, 0, 5)
	for name, present := range map[string]bool{
		"applications.backend_tls_ca_file":     hasTLSCA,
		"applications.backend_tls_server_name": hasTLSServerName,
		"applications.backend_tls_verify":      hasTLSVerify,
		"operator_enrollment":                  hasEnrollment,
		"users.session_version":                hasSessionVersion,
	} {
		if !present {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "Security Schema",
			Status:   StatusFail,
			Message:  "Missing required schema objects: " + strings.Join(missing, ", "),
		})
		return checks
	}
	checks = append(checks, CheckResult{
		Category: "Database",
		Name:     "Security Schema",
		Status:   StatusOK,
		Message:  "Security migrations 016-018 are present",
	})

	// Check table counts
	var appCount, certCount, userCount int
	err = tx.QueryRowContext(ctxTimeout, `
		SELECT
			(SELECT COUNT(*) FROM applications),
			(SELECT COUNT(*) FROM certificates),
			(SELECT COUNT(*) FROM users)`).Scan(&appCount, &certCount, &userCount)
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "Database",
			Name:     "Data Entities",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("Could not count configured objects: %v", err),
		})
		return checks
	}

	checks = append(checks, CheckResult{
		Category: "Database",
		Name:     "Data Entities",
		Status:   StatusOK,
		Message:  fmt.Sprintf("Objects: %d applications, %d certificates, %d operators", appCount, certCount, userCount),
	})

	return checks
}

func checkHAProxy(stateDir string) []CheckResult {
	var checks []CheckResult

	haproxyBin, err := exec.LookPath("haproxy")
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "HAProxy",
			Name:     "Binary Installation",
			Status:   StatusFail,
			Message:  "haproxy executable not found in PATH",
		})
		return checks
	}

	checks = append(checks, CheckResult{
		Category: "HAProxy",
		Name:     "Binary Installation",
		Status:   StatusOK,
		Message:  fmt.Sprintf("Found haproxy at %s", haproxyBin),
	})

	// Check config file syntax
	cfgPath := filepath.Join(stateDir, "haproxy", "haproxy.cfg")
	if _, err := os.Stat(cfgPath); err != nil {
		checks = append(checks, CheckResult{
			Category: "HAProxy",
			Name:     "Configuration File",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("No generated configuration file at %s (run easy-waf-admin apply-edge or start API)", cfgPath),
		})
	} else {
		cmd := exec.Command(haproxyBin, "-c", "-f", cfgPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			checks = append(checks, CheckResult{
				Category: "HAProxy",
				Name:     "Configuration Syntax",
				Status:   StatusFail,
				Message:  fmt.Sprintf("Configuration validation error: %v", err),
				Details:  strings.TrimSpace(string(out)),
			})
		} else {
			checks = append(checks, CheckResult{
				Category: "HAProxy",
				Name:     "Configuration Syntax",
				Status:   StatusOK,
				Message:  fmt.Sprintf("Syntax valid (%s)", cfgPath),
			})
		}
	}

	// Check stats socket
	sockPath := "/run/haproxy/admin.sock"
	if _, err := os.Stat(sockPath); err == nil {
		conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
		if err != nil {
			checks = append(checks, CheckResult{
				Category: "HAProxy",
				Name:     "Stats Socket",
				Status:   StatusWarn,
				Message:  fmt.Sprintf("Socket %s exists but is not answering: %v", sockPath, err),
			})
		} else {
			_ = conn.Close()
			checks = append(checks, CheckResult{
				Category: "HAProxy",
				Name:     "Stats Socket",
				Status:   StatusOK,
				Message:  fmt.Sprintf("Socket %s responsive", sockPath),
			})
		}
	}

	return checks
}

func checkServices(ctx context.Context) []CheckResult {
	var checks []CheckResult

	units := []struct {
		name     string
		required bool
	}{
		{"easy-waf-api", true},
		{"easy-waf-acmed", true},
		{"easy-waf-hostd", true},
		{"haproxy", true},
		{"crowdsec", false},
		{"fail2ban", false},
	}

	for _, u := range units {
		ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(ctxTimeout, "systemctl", "is-active", u.name) //nolint:gosec
		out, err := cmd.Output()
		cancel()

		state := strings.TrimSpace(string(out))
		if err == nil && state == "active" {
			checks = append(checks, CheckResult{
				Category: "Services",
				Name:     u.name,
				Status:   StatusOK,
				Message:  "Service is active (running)",
			})
		} else {
			status := StatusWarn
			if u.required {
				status = StatusFail
			}
			msg := fmt.Sprintf("Service is %s", state)
			if state == "" {
				msg = "Service status unavailable (inactive or not installed)"
			}
			checks = append(checks, CheckResult{
				Category: "Services",
				Name:     u.name,
				Status:   status,
				Message:  msg,
			})
		}
	}

	return checks
}

func checkGeoIP(stateDir string) []CheckResult {
	var checks []CheckResult
	p := filepath.Join(stateDir, "geoip", "GeoLite2-Country.mmdb")
	st, err := os.Stat(p)
	if err != nil {
		checks = append(checks, CheckResult{
			Category: "GeoIP",
			Name:     "Country Database",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("MMDB file missing at %s (run scripts/update-geoip-db.sh)", p),
		})
		return checks
	}

	age := time.Since(st.ModTime())
	if age > 45*24*time.Hour {
		checks = append(checks, CheckResult{
			Category: "GeoIP",
			Name:     "Country Database",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("MMDB file is %d days old (recommended update every 30 days)", int(age.Hours()/24)),
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "GeoIP",
			Name:     "Country Database",
			Status:   StatusOK,
			Message:  fmt.Sprintf("MMDB file present (%s, %d days old)", formatBytes(uint64(st.Size())), int(age.Hours()/24)), //nolint:gosec
		})
	}

	return checks
}

func checkCertificates(stateDir string) []CheckResult {
	var checks []CheckResult
	certsDir := filepath.Join(stateDir, "certs")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		// certs dir may not exist yet if fresh install
		return checks
	}

	now := time.Now()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fullchain := filepath.Join(certsDir, entry.Name(), "fullchain.pem")
		raw, err := os.ReadFile(fullchain)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		domain := cert.Subject.CommonName
		if len(cert.DNSNames) > 0 {
			domain = cert.DNSNames[0]
		}

		switch {
		case now.After(cert.NotAfter):
			checks = append(checks, CheckResult{
				Category: "Certificates",
				Name:     domain,
				Status:   StatusFail,
				Message:  fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
			})
		case cert.NotAfter.Sub(now) < 15*24*time.Hour:
			days := int(cert.NotAfter.Sub(now).Hours() / 24)
			checks = append(checks, CheckResult{
				Category: "Certificates",
				Name:     domain,
				Status:   StatusWarn,
				Message:  fmt.Sprintf("Certificate expires in %d days (%s)", days, cert.NotAfter.Format("2006-01-02")),
			})
		default:
			checks = append(checks, CheckResult{
				Category: "Certificates",
				Name:     domain,
				Status:   StatusOK,
				Message:  fmt.Sprintf("Valid until %s", cert.NotAfter.Format("2006-01-02")),
			})
		}
	}

	return checks
}

// PrintHumanReport renders the diagnostic report to w with ANSI colors.
func PrintHumanReport(w io.Writer, r DoctorReport) {
	fmt.Fprintf(w, "=== Easy Home WAF Diagnostic Report (%s) ===\n\n", r.Timestamp.Format("2006-01-02 15:04:05 MST"))

	currCat := ""
	for _, c := range r.Checks {
		if c.Category != currCat {
			currCat = c.Category
			fmt.Fprintf(w, "[%s]\n", currCat)
		}

		badge := fmt.Sprintf("[%s]", c.Status)
		fmt.Fprintf(w, "  %-6s  %-30s  %s\n", badge, c.Name, c.Message)
		if c.Details != "" {
			fmt.Fprintf(w, "          Details: %s\n", c.Details)
		}
	}

	fmt.Fprintf(w, "\n--- Summary: %s ---\n", r.Summary)
}

// PrintJSONReport writes the report as indented JSON.
func PrintJSONReport(w io.Writer, r DoctorReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
