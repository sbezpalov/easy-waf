// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]job    `yaml:"jobs"`
}

type job struct {
	Uses            string            `yaml:"uses"`
	Needs           any               `yaml:"needs"`
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Permissions     map[string]string `yaml:"permissions"`
	Secrets         any               `yaml:"secrets"`
	Steps           []map[string]any  `yaml:"steps"`
	Strategy        struct {
		Matrix struct {
			Include []struct {
				Arch string `yaml:"arch"`
			} `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
}

func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(body, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func requireSuccessDependency(t *testing.T, j job, dependency string) {
	t.Helper()
	found := j.Needs == dependency
	if list, ok := j.Needs.([]any); ok {
		for _, v := range list {
			found = found || v == dependency
		}
	}
	if !found || j.If != "" || j.ContinueOnError != nil {
		t.Fatalf("publication must require normal success of %s without bypass conditions", dependency)
	}
}

func TestReleaseRequiresSameCommitCI(t *testing.T) {
	release := readWorkflow(t, "release.yml")
	validation, ok := release.Jobs["validate"]
	if !ok || validation.Uses != "./.github/workflows/ci.yml" {
		t.Fatal("release must call same-commit CI before publishing")
	}
	if validation.If != "" || validation.ContinueOnError != nil || validation.Secrets != nil {
		t.Fatal("validation must not be skipped, softened or inherit publishing secrets")
	}
	if len(validation.Permissions) != 1 || validation.Permissions["contents"] != "read" {
		t.Fatal("validation must have only read access")
	}
	requireSuccessDependency(t, release.Jobs["build-packages"], "validate")
	offline := release.Jobs["offline-bundle"]
	requireSuccessDependency(t, offline, "build-packages")
	architectures := make(map[string]int)
	for _, entry := range offline.Strategy.Matrix.Include {
		architectures[entry.Arch]++
	}
	if len(architectures) != 2 || architectures["amd64"] != 1 || architectures["arm64"] != 1 {
		t.Fatalf("expected exactly one offline build for each architecture, got %v", architectures)
	}
	requireSuccessDependency(t, release.Jobs["publish"], "build-packages")
	requireSuccessDependency(t, release.Jobs["publish"], "offline-bundle")
	ci := readWorkflow(t, "ci.yml")
	if _, ok := ci.On["workflow_call"]; !ok {
		t.Fatal("CI must support calls from tag releases")
	}
	for _, name := range []string{"lint-and-test", "verify", "haproxy-config-test"} {
		j, ok := ci.Jobs[name]
		if !ok || len(j.Steps) == 0 || j.If != "" || j.ContinueOnError != nil {
			t.Fatalf("required CI job %s must run and fail normally", name)
		}
		for _, step := range j.Steps {
			if _, ok := step["continue-on-error"]; ok {
				t.Fatalf("CI job %s contains a softened step", name)
			}
		}
	}
}

func TestReleaseVerifiesSignedArtifactsBeforePublishing(t *testing.T) {
	release := readWorkflow(t, "release.yml")
	built, signed, verified, staged := -1, -1, -1, -1
	for index, step := range release.Jobs["build-packages"].Steps {
		switch step["name"] {
		case "Build amd64 and arm64 tarballs and packages":
			built = index
			run, _ := step["run"].(string)
			for _, command := range []string{
				`GOFLAGS=-buildvcs=true EASY_WAF_ARCH="$arch" make deb`,
				`go version -m "dist/$binary"`,
				"vcs.revision",
				"vcs.modified=false",
			} {
				if !strings.Contains(run, command) {
					t.Errorf("release build must check source provenance with %q", command)
				}
			}
			if step["if"] != nil || step["continue-on-error"] != nil {
				t.Error("source provenance verification must not be skipped or softened")
			}
		case "Sign SHA256SUMS":
			signed = index
		case "Verify signed release artifacts before publication":
			verified = index
			run, _ := step["run"].(string)
			for _, command := range []string{
				"set -euo pipefail",
				"source scripts/lib/release-verify.sh",
				`easy_waf_verify_github_blob SHA256SUMS SHA256SUMS.sigstore.json "$GITHUB_REPOSITORY" "$GITHUB_REF_NAME"`,
				"sha256sum --check --strict SHA256SUMS",
			} {
				if !strings.Contains(run, command) {
					t.Errorf("publication verifier must run %q", command)
				}
			}
			if step["if"] != nil || step["continue-on-error"] != nil {
				t.Error("signature verification must not be skipped or softened")
			}
		case "Stage signed release packages":
			staged = index
		}
	}
	if built < 0 || signed <= built || verified <= signed || staged <= verified {
		t.Fatal("packages must pass source provenance verification, signing and signature verification before staging")
	}
	if len(release.Permissions) != 1 || release.Permissions["contents"] != "read" {
		t.Fatal("release jobs must default to read-only repository access")
	}
	for name, job := range release.Jobs {
		if name != "publish" && job.Permissions["contents"] == "write" {
			t.Errorf("only the final job may publish, found write access in %s", name)
		}
	}
	publication := release.Jobs["publish"]
	if len(publication.Permissions) != 1 || publication.Permissions["contents"] != "write" {
		t.Fatal("final job must have only repository write access")
	}
	wantArtifacts := map[string]bool{
		"release-packages":  false,
		"offline-iso-amd64": false,
		"offline-iso-arm64": false,
	}
	published := false
	for _, step := range publication.Steps {
		if step["if"] != nil || step["continue-on-error"] != nil {
			t.Fatal("publication prerequisites must not be skipped or softened")
		}
		if uses, _ := step["uses"].(string); strings.HasPrefix(uses, "actions/download-artifact@") {
			options, _ := step["with"].(map[string]any)
			name, _ := options["name"].(string)
			seen, expected := wantArtifacts[name]
			if published || !expected || seen || options["path"] != "release-assets" || options["run-id"] != nil {
				t.Fatalf("unexpected release artifact download: %v", options)
			}
			wantArtifacts[name] = true
		}
		if step["run"] == "bash scripts/publish-release.sh release-assets" {
			if published {
				t.Fatal("publication must run once")
			}
			for name, seen := range wantArtifacts {
				if !seen {
					t.Errorf("missing same-run artifact %s before publication", name)
				}
			}
			published = true
		}
	}
	if !published {
		t.Fatal("final job must verify and publish the complete set")
	}
}
