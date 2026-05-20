package admin

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

// PasswordAlphabet is URL- and shell-safe (no quotes/spaces); length 19 from this set is strong enough for dev appliances.
const PasswordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomAlphanumericPassword returns n random characters from PasswordAlphabet.
func RandomAlphanumericPassword(n int) (string, error) {
	if n < 8 || n > 128 {
		return "", fmt.Errorf("password length must be between 8 and 128")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var out strings.Builder
	out.Grow(n)
	for i := 0; i < n; i++ {
		out.WriteByte(PasswordAlphabet[int(buf[i])%len(PasswordAlphabet)])
	}
	return out.String(), nil
}

// PostgresConnParts holds connection fields parsed from a postgres:// URL.
type PostgresConnParts struct {
	User    string
	Host    string
	Port    string
	DBName  string
	SSLMode string
}

// ParsePostgresURL parses postgres:// or postgresql:// DSN (password may be empty).
func ParsePostgresURL(dsn string) (PostgresConnParts, error) {
	var z PostgresConnParts
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil {
		return z, err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return z, fmt.Errorf("expected postgres URL scheme, got %q", u.Scheme)
	}
	if u.User == nil {
		return z, fmt.Errorf("postgres URL missing user")
	}
	user := u.User.Username()
	if !isSimplePGIdent(user) {
		return z, fmt.Errorf("unsupported postgres user name %q (use letters, digits, underscore)", user)
	}
	z.User = user
	host := u.Hostname()
	if host == "" {
		return z, fmt.Errorf("postgres URL missing host")
	}
	z.Host = host
	z.Port = u.Port()
	if z.Port == "" {
		z.Port = "5432"
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return z, fmt.Errorf("postgres URL missing database name in path")
	}
	if !isSimplePGIdent(db) {
		return z, fmt.Errorf("unsupported database name %q", db)
	}
	z.DBName = db
	q := u.Query()
	z.SSLMode = q.Get("sslmode")
	if z.SSLMode == "" {
		z.SSLMode = "disable"
	}
	return z, nil
}

func isSimplePGIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			continue
		}
		return false
	}
	return true
}

// BuildPostgresURL builds a postgres DSN with URL-encoded password.
func BuildPostgresURL(user, password string, parts PostgresConnParts) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(parts.Host, parts.Port),
		Path:   "/" + parts.DBName,
	}
	q := url.Values{}
	q.Set("sslmode", parts.SSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

// AlterPostgresRolePassword runs ALTER USER as the OS postgres superuser (local peer auth).
func AlterPostgresRolePassword(role, password string) error {
	if !isSimplePGIdent(role) {
		return fmt.Errorf("refusing ALTER for role name %q", role)
	}
	// Password uses only PasswordAlphabet — safe inside single-quoted SQL literal.
	sql := fmt.Sprintf("ALTER USER %s WITH PASSWORD '%s';", role, strings.ReplaceAll(password, "'", "''"))
	if err := runPostgresSuperuserSQL(sql); err != nil {
		return err
	}
	return nil
}

func runPostgresSuperuserSQL(sql string) error {
	if _, err := exec.LookPath("runuser"); err != nil {
		return fmt.Errorf("runuser not in PATH (install util-linux): %w", err)
	}
	cmd := exec.Command("runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-c", sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("runuser postgres psql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DefaultBootstrapReportPath is where generated secrets are written (root-readable only).
const DefaultBootstrapReportPath = "/root/easy-waf-bootstrap-credentials.txt"

// WriteBootstrapReport writes a root-only file with generated secrets (not the GUI password).
func WriteBootstrapReport(path, content string) error {
	if path == "" {
		path = DefaultBootstrapReportPath
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
