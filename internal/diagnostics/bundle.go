// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/commandoutput"
	"github.com/easy-waf/easy-waf/internal/commandprocess"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/store"
)

// MaxBundleBytes caps the uncompressed tar size for API-generated bundles.
const MaxBundleBytes = 40 << 20

// Params configures an API-side diagnostics bundle (same spirit as scripts/diagnostics.sh).
type Params struct {
	StateDir string
	EnvPath  string
	Store    *store.Store
	Settings config.GlobalSettings
	Version  string
}

// BuildSupportBundleGzip returns a gzip-compressed tar (bytes) for download.
// The API process is usually unprivileged (systemd NoNewPrivileges); some host probes may be empty or show permission errors — see docs/DIAGNOSTICS.md.
func BuildSupportBundleGzip(ctx context.Context, p Params) ([]byte, error) {
	if p.Store == nil {
		return nil, fmt.Errorf("diagnostics: store is nil")
	}
	envPath := p.EnvPath
	if envPath == "" {
		envPath = "/etc/easy-waf/easy-waf.env"
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	prefix := fmt.Sprintf("easy-waf-diag-api-%s/", stamp)

	var gzipBuf bytes.Buffer
	gw := gzip.NewWriter(&gzipBuf)
	gw.ModTime = time.Now().UTC()
	dst := &bundleWriter{dst: gw, remaining: MaxBundleBytes}
	if err := writeSupportBundleTar(ctx, dst, p, prefix, envPath); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return gzipBuf.Bytes(), nil
}

// Count tar headers, padding and end markers before compression.
type bundleWriter struct {
	dst       io.Writer
	remaining int
}

func (w *bundleWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, fmt.Errorf("diagnostics: bundle exceeds limit of %d bytes", MaxBundleBytes)
	}
	n, err := w.dst.Write(p)
	w.remaining -= n
	return n, err
}

func writeSupportBundleTar(ctx context.Context, w io.Writer, p Params, prefix, envPath string) error {
	tw := tar.NewWriter(w)

	ver := strings.TrimSpace(p.Version)
	if ver == "" {
		ver = strings.TrimSpace(os.Getenv("EASY_WAF_VERSION"))
	}
	if ver == "" {
		ver = "unknown"
	}
	host := hostspec.ReportHostname()
	manifest := fmt.Sprintf(
		"easy-waf-diagnostics-format v1 (api)\n"+
			"created_utc=%s\n"+
			"hostname=%s\n"+
			"version=%s\n"+
			"bundle_source=api\n"+
			"note=see docs/DIAGNOSTICS.md for differences vs root script\n",
		time.Now().UTC().Format(time.RFC3339), host, ver,
	)
	if err := addTarBytes(tw, prefix+"MANIFEST.txt", []byte(manifest), 0o644); err != nil {
		return err
	}

	run := func(rel string, timeout time.Duration, name string, args ...string) error {
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx2, name, args...)
		cmd.Env = os.Environ()
		out, _ := probeOutput(cmd, true)
		return addTarBytes(tw, prefix+rel, out, 0o644)
	}

	for _, probe := range []struct {
		file, command string
		timeout       time.Duration
		args          []string
	}{
		{"uname", "uname", 5 * time.Second, []string{"-a"}},
		{"os-release", "cat", 2 * time.Second, []string{"/etc/os-release"}},
		{"hostnamectl", "hostnamectl", 5 * time.Second, nil},
		{"free-m", "free", 5 * time.Second, []string{"-m"}},
		{"df-h", "df", 8 * time.Second, []string{"-h"}},
		{"uptime", "uptime", 3 * time.Second, nil},
		{"ss-tlnp", "ss", 8 * time.Second, []string{"-tlnp"}},
		{"aa-status", "aa-status", 5 * time.Second, nil},
	} {
		if err := run("system/"+probe.file+".txt", probe.timeout, probe.command, probe.args...); err != nil {
			return err
		}
	}
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	if out, err := probeOutput(exec.CommandContext(ctx2, "aa-status", "--enabled"), true); err == nil {
		if err := addTarBytes(tw, prefix+"system/aa-status-enabled.txt", out, 0o644); err != nil {
			cancel()
			return err
		}
	}
	cancel()

	// easy-waf-hostd belongs here as much as the other two: every privileged
	// operation the appliance performs goes through the broker, so a bundle
	// collected after a failed host update, firewall apply or user change was
	// missing the one unit that could explain it.
	units := []string{"easy-waf-api", "easy-waf-acmed", "easy-waf-hostd", "haproxy", "crowdsec", "fail2ban", "nftables"}
	for _, u := range units {
		safe := strings.ReplaceAll(u, "/", "-")
		if err := run(fmt.Sprintf("systemctl/status-%s.txt", safe), 20*time.Second, "systemctl", "status", u, "--no-pager", "-l"); err != nil {
			return err
		}
		ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
		out, _ := probeOutput(exec.CommandContext(ctx2, "systemctl", "is-enabled", u), true)
		cancel()
		line := append([]byte("is-enabled: "), out...)
		if err := addTarBytes(tw, prefix+fmt.Sprintf("systemctl/is-enabled-%s.txt", safe), line, 0o644); err != nil {
			return err
		}
	}
	if err := addTarBytes(tw, prefix+"systemctl/state-easy-waf-mcpd.txt", mcpServiceState(ctx), 0o644); err != nil {
		return err
	}

	for _, pair := range []struct{ unit, dst string }{
		{"easy-waf-api", "logs/journal-easy-waf-api.txt"},
		{"easy-waf-acmed", "logs/journal-easy-waf-acmed.txt"},
		{"easy-waf-hostd", "logs/journal-easy-waf-hostd.txt"},
		{"haproxy", "logs/journal-haproxy.txt"},
	} {
		ctx2, cancel := context.WithTimeout(ctx, 45*time.Second)
		out, _ := probeOutput(exec.CommandContext(ctx2, "journalctl", "-u", pair.unit, "--since", "24 hours ago", "-n", "500", "--no-pager"), true) //nolint:gosec
		cancel()
		if err := addTarBytes(tw, prefix+pair.dst, out, 0o644); err != nil {
			return err
		}
	}

	raw, err := os.ReadFile(envPath)
	if err != nil {
		raw = processEnvSnapshot(envPath, err)
	}
	if err := addTarBytes(tw, prefix+"config/easy-waf.env.masked", MaskEasyWAFEnvContent(raw), 0o640); err != nil {
		return err
	}

	cfgPath, cfgPathErr := managedHAProxyConfigPath(p.StateDir, p.Settings.HAProxyConfigPath)
	if cfgPathErr != nil {
		if err := addTarBytes(tw, prefix+"config/haproxy.cfg", []byte("(refused unsafe configured path: "+cfgPathErr.Error()+")\n"), 0o644); err != nil {
			return err
		}
	} else if raw, err := os.ReadFile(cfgPath); err == nil {
		if err := addTarBytes(tw, prefix+"config/haproxy.cfg", MaskHAProxyConfigContent(raw), 0o640); err != nil {
			return err
		}
	} else {
		if err := addTarBytes(tw, prefix+"config/haproxy.cfg", []byte("(missing "+cfgPath+")\n"), 0o644); err != nil {
			return err
		}
	}

	_, _, crtPath := haproxy.Paths(p.StateDir)
	var crtNames []byte
	if raw, err := os.ReadFile(crtPath); err == nil {
		var b strings.Builder
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			b.WriteString(filepath.Base(line))
			b.WriteByte('\n')
		}
		crtNames = []byte(b.String())
	} else {
		crtNames = []byte("(missing " + crtPath + ")\n")
	}
	if err := addTarBytes(tw, prefix+"config/crt-list-filenames.txt", crtNames, 0o644); err != nil {
		return err
	}

	const hb = "/usr/sbin/haproxy"
	if err := run("validation/haproxy-vv.txt", 15*time.Second, hb, "-vv"); err != nil {
		return err
	}
	var haproxyCheckOut []byte
	if cfgPathErr != nil {
		haproxyCheckOut = []byte("validation skipped: " + cfgPathErr.Error() + "\n")
	} else {
		ctx2, cancel = context.WithTimeout(ctx, 30*time.Second)
		haproxyCheckOut, _ = probeOutput(exec.CommandContext(ctx2, hb, "-c", "-f", cfgPath), true)
		cancel()
	}
	if err := addTarBytes(tw, prefix+"validation/haproxy-check.txt", MaskHAProxyConfigContent(haproxyCheckOut), 0o644); err != nil {
		return err
	}

	revs, err := p.Store.ListConfigRevisions(ctx, 5)
	var revBody []byte
	if err != nil {
		revBody = []byte("(query failed: " + err.Error() + ")\n")
	} else {
		var b strings.Builder
		b.WriteString("id\tsha256\tcreated_at\n")
		for _, r := range revs {
			fmt.Fprintf(&b, "%d\t%s\t%s\n", r.ID, r.HAProxySHA256, r.At.UTC().Format(time.RFC3339))
		}
		revBody = []byte(b.String())
	}
	if err := addTarBytes(tw, prefix+"sql/config_revisions.txt", revBody, 0o644); err != nil {
		return err
	}

	if err := run("firewall/nft-ruleset.txt", 20*time.Second, "nft", "list", "ruleset"); err != nil {
		return err
	}
	if raw, err := os.ReadFile("/etc/nftables/easy-waf.nft"); err == nil {
		if err := addTarBytes(tw, prefix+"firewall/easy-waf.nft", raw, 0o644); err != nil {
			return err
		}
	}

	return tw.Close()
}

// Keep the entry when a probe overflows, but never treat a prefix as a
// complete diagnostic or pass a partial configuration to a redactor.
func probeOutput(cmd *exec.Cmd, includeStderr bool) ([]byte, error) {
	var capture commandoutput.Capture
	cmd.Stdout = capture.Stdout()
	if includeStderr {
		cmd.Stderr = cmd.Stdout
	}
	commandprocess.Prepare(cmd)
	runErr := cmd.Run()
	err := errors.Join(runErr, commandprocess.Finish(cmd, true))
	out, _, overflow := capture.Result()
	if overflow != nil {
		return fmt.Appendf(nil, "(output omitted: probe exceeded %d bytes)\n", commandoutput.Limit), err
	}
	return out, err
}

func mcpServiceState(ctx context.Context) []byte {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := probeOutput(exec.CommandContext(ctx, "systemctl", "show", "--no-pager",
		"-p", "LoadState", "-p", "UnitFileState", "-p", "ActiveState", "-p", "SubState",
		"-p", "Result", "-p", "ConditionResult", "-p", "ExecMainStatus", "easy-waf-mcpd.service"), false)
	if err != nil {
		return []byte("MCP service state unavailable\n")
	}
	return out
}

func managedHAProxyConfigPath(stateDir, configured string) (string, error) {
	managedDir, err := filepath.Abs(filepath.Join(stateDir, "haproxy"))
	if err != nil {
		return "", err
	}
	candidate := strings.TrimSpace(configured)
	if candidate == "" {
		_, candidate, _ = haproxy.Paths(stateDir)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	if err := requirePathWithin(managedDir, candidate); err != nil {
		return "", err
	}
	resolvedDir, err := filepath.EvalSymlinks(managedDir)
	if err != nil {
		return "", fmt.Errorf("resolve managed HAProxy directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		// A genuinely missing config is safe to report as missing, but an
		// existing dangling symlink must fail closed. Resolving the parent also
		// catches a dangling or escaping symlink in an intermediate component.
		if _, lstatErr := os.Lstat(candidate); lstatErr == nil || !os.IsNotExist(lstatErr) {
			return "", fmt.Errorf("resolve managed HAProxy config path: %w", err)
		}
		resolvedParent, parentErr := filepath.EvalSymlinks(filepath.Dir(candidate))
		if parentErr != nil {
			return "", fmt.Errorf("resolve managed HAProxy config directory: %w", parentErr)
		}
		if err := requirePathWithin(resolvedDir, resolvedParent); err != nil {
			return "", err
		}
		return candidate, nil
	}
	if err := requirePathWithin(resolvedDir, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func requirePathWithin(base, candidate string) error {
	rel, err := filepath.Rel(base, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("path is outside managed HAProxy directory")
	}
	return nil
}

func addTarBytes(tw *tar.Writer, name string, body []byte, mode int64) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(body)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

// envSnapshotPrefixes select the process variables that come from easy-waf.env.
var envSnapshotPrefixes = []string{"EASY_WAF_", "DATABASE_URL", "CROWDSEC_", "ACME_", "GEOIP_", "MAXMIND_"}

// processEnvSnapshot stands in for easy-waf.env, which is root-only: the API
// cannot read it, but systemd handed it the same variables. Mask each complete
// entry before flattening; public LF/CR are escaped so they cannot fake entries.
func processEnvSnapshot(envPath string, readErr error) []byte {
	header := "# " + envPath + " could not be read (" + readErr.Error() + "; root-only by design).\n" +
		"# Variables of the running API process instead. For the file: sudo easy-waf-diagnostics\n"
	vars := make([]string, 0, len(envSnapshotPrefixes))
	for _, kv := range os.Environ() {
		for _, prefix := range envSnapshotPrefixes {
			if strings.HasPrefix(kv, prefix) {
				kv = MaskEasyWAFEnvLine(kv)
				kv = strings.ReplaceAll(kv, "\r", "\\r")
				kv = strings.ReplaceAll(kv, "\n", "\\n")
				vars = append(vars, kv)
				break
			}
		}
	}
	sort.Strings(vars)
	return []byte(header + strings.Join(vars, "\n") + "\n")
}
