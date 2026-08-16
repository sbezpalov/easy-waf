//go:build integration

package haproxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/easy-waf/easy-waf/internal/apply"
)

// TestGoldenConfigsPassHaproxyCheck requires:
//   - haproxy in PATH
//   - cwd = internal/haproxy (normal for go test ./internal/haproxy)
//   - committed testdata/golden/*.cfg, *.crt-list.txt, certs, spoe, ipbl
func TestGoldenConfigsPassHaproxyCheck(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH (install haproxy to run integration golden validation)")
	}

	for _, name := range goldenScenarioNames {
		t.Run(name, func(t *testing.T) {
			cfgPath := filepath.Join("testdata", "golden", name+".cfg")
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			// HAProxy 3.x requires an absolute stats socket path, but sun_path is limited (~97 bytes).
			// t.TempDir() already includes a long test name; keep socket filename very short.
			d := t.TempDir()
			absSock := filepath.Join(d, "s.sock")
			cfgBody := rewriteStatsSocketPathForHAProxyCheck(raw, absSock)
			// Backend-TLS fixtures record an operator CA path that exists only on the
			// appliance they were written for, and haproxy -c opens ca-file for real.
			cfgBody = rewriteCAFilePathForHAProxyCheck(cfgBody, goldenCAFileForCheck(t, d))
			cfgBody = augmentGoldenHAProxyCfgForHaproxyCheck(cfgBody)
			tmp := filepath.Join(d, "c.cfg")
			if err := os.WriteFile(tmp, cfgBody, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := apply.Validate(hx, tmp); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// goldenCAFileForCheck materializes a CA bundle for `haproxy -c` to open,
// reusing a committed certificate fixture so no key material is generated here.
func goldenCAFileForCheck(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join("testdata", "golden", "certs", "bundle-a.pem")
	pem, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read CA fixture %s: %v", src, err)
	}
	dst := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(dst, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}
