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
			cfgBody := augmentGoldenHAProxyCfgForHaproxyCheck(raw)
			tmp := filepath.Join(t.TempDir(), name+".cfg")
			if err := os.WriteFile(tmp, cfgBody, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := apply.Validate(hx, tmp); err != nil {
				t.Fatal(err)
			}
		})
	}
}
