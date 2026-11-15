// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v4"
)

type workflow struct {
	On   map[string]any `yaml:"on"`
	Jobs map[string]job `yaml:"jobs"`
}

type job struct {
	Uses            string            `yaml:"uses"`
	Needs           any               `yaml:"needs"`
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Permissions     map[string]string `yaml:"permissions"`
	Secrets         any               `yaml:"secrets"`
	Steps           []map[string]any  `yaml:"steps"`
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
	build, ok := release.Jobs["build-and-release"]
	if !ok {
		t.Fatal("missing artifact publication job")
	}
	requireSuccessDependency(t, build, "validate")
	offline, ok := release.Jobs["offline-bundle"]
	if !ok {
		t.Fatal("missing offline publication job")
	}
	requireSuccessDependency(t, offline, "build-and-release")
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
