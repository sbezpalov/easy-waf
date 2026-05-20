package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
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

	var tarBuf bytes.Buffer
	if err := writeSupportBundleTar(ctx, &tarBuf, p, prefix, envPath); err != nil {
		return nil, err
	}
	if tarBuf.Len() > MaxBundleBytes {
		return nil, fmt.Errorf("diagnostics: bundle size %d exceeds limit %d", tarBuf.Len(), MaxBundleBytes)
	}
	var gzipBuf bytes.Buffer
	gw := gzip.NewWriter(&gzipBuf)
	gw.Header.ModTime = time.Now().UTC()
	if _, err := io.Copy(gw, bytes.NewReader(tarBuf.Bytes())); err != nil {
		_ = gw.Close()
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return gzipBuf.Bytes(), nil
}

func writeSupportBundleTar(ctx context.Context, w io.Writer, p Params, prefix, envPath string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	ver := strings.TrimSpace(p.Version)
	if ver == "" {
		ver = strings.TrimSpace(os.Getenv("EASY_WAF_VERSION"))
	}
	if ver == "" {
		ver = "unknown"
	}
	host, _ := os.Hostname()
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
		out, _ := cmd.CombinedOutput()
		return addTarBytes(tw, prefix+rel, out, 0o644)
	}

	_ = run("system/uname.txt", 5*time.Second, "uname", "-a")
	_ = run("system/os-release.txt", 2*time.Second, "cat", "/etc/os-release")
	_ = run("system/hostnamectl.txt", 5*time.Second, "hostnamectl")
	_ = run("system/free-m.txt", 5*time.Second, "free", "-m")
	_ = run("system/df-h.txt", 8*time.Second, "df", "-h")
	_ = run("system/uptime.txt", 3*time.Second, "uptime")
	_ = run("system/ss-tlnp.txt", 8*time.Second, "ss", "-tlnp")
	_ = run("system/aa-status.txt", 5*time.Second, "aa-status")
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	if out, err := exec.CommandContext(ctx2, "aa-status", "--enabled").CombinedOutput(); err == nil {
		_ = addTarBytes(tw, prefix+"system/aa-status-enabled.txt", out, 0o644)
	}
	cancel()

	units := []string{"easy-waf-api", "easy-waf-acmed", "haproxy", "crowdsec", "fail2ban", "nftables"}
	for _, u := range units {
		safe := strings.ReplaceAll(u, "/", "-")
		_ = run(fmt.Sprintf("systemctl/status-%s.txt", safe), 20*time.Second, "systemctl", "status", u, "--no-pager", "-l")
		ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
		out, _ := exec.CommandContext(ctx2, "systemctl", "is-enabled", u).CombinedOutput()
		cancel()
		line := append([]byte("is-enabled: "), out...)
		if err := addTarBytes(tw, prefix+fmt.Sprintf("systemctl/is-enabled-%s.txt", safe), line, 0o644); err != nil {
			return err
		}
	}

	for _, pair := range []struct{ unit, dst string }{
		{"easy-waf-api", "logs/journal-easy-waf-api.txt"},
		{"easy-waf-acmed", "logs/journal-easy-waf-acmed.txt"},
		{"haproxy", "logs/journal-haproxy.txt"},
	} {
		ctx2, cancel := context.WithTimeout(ctx, 45*time.Second)
		out, _ := exec.CommandContext(ctx2, "journalctl", "-u", pair.unit, "--since", "24 hours ago", "-n", "500", "--no-pager").CombinedOutput()
		cancel()
		if err := addTarBytes(tw, prefix+pair.dst, out, 0o644); err != nil {
			return err
		}
	}

	if raw, err := os.ReadFile(envPath); err == nil {
		if err := addTarBytes(tw, prefix+"config/easy-waf.env.masked", MaskEasyWAFEnvContent(raw), 0o640); err != nil {
			return err
		}
	} else {
		if err := addTarBytes(tw, prefix+"config/easy-waf.env.masked", []byte("(could not read: "+err.Error()+")\n"), 0o644); err != nil {
			return err
		}
	}

	cfgPath := strings.TrimSpace(p.Settings.HAProxyConfigPath)
	if cfgPath == "" {
		_, def, _ := haproxy.Paths(p.StateDir)
		cfgPath = def
	}
	if raw, err := os.ReadFile(cfgPath); err == nil {
		if err := addTarBytes(tw, prefix+"config/haproxy.cfg", raw, 0o640); err != nil {
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

	hb := strings.TrimSpace(p.Settings.HAProxyBinary)
	if hb == "" {
		hb = "haproxy"
	}
	_ = run("validation/haproxy-vv.txt", 15*time.Second, hb, "-vv")
	ctx2, cancel = context.WithTimeout(ctx, 30*time.Second)
	haproxyCheckOut, _ := exec.CommandContext(ctx2, hb, "-c", "-f", cfgPath).CombinedOutput()
	cancel()
	if err := addTarBytes(tw, prefix+"validation/haproxy-check.txt", haproxyCheckOut, 0o644); err != nil {
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
			b.WriteString(fmt.Sprintf("%d\t%s\t%s\n", r.ID, r.HAProxySHA256, r.At.UTC().Format(time.RFC3339)))
		}
		revBody = []byte(b.String())
	}
	if err := addTarBytes(tw, prefix+"sql/config_revisions.txt", revBody, 0o644); err != nil {
		return err
	}

	_ = run("firewall/nft-ruleset.txt", 20*time.Second, "nft", "list", "ruleset")
	if raw, err := os.ReadFile("/etc/nftables/easy-waf.nft"); err == nil {
		_ = addTarBytes(tw, prefix+"firewall/easy-waf.nft", raw, 0o644)
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
