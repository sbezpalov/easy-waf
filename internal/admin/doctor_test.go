package admin

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		if got := formatBytes(tt.bytes); got != tt.want {
			t.Errorf("formatBytes(%d) = %q; want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestCheckStateDir(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o750)
	checks := checkStateDir(dir)
	if len(checks) == 0 {
		t.Fatal("expected checks for valid stateDir")
	}
	if checks[0].Status != StatusOK {
		t.Errorf("expected StatusOK for temp stateDir, got %v", checks[0].Status)
	}

	// Nonexistent dir
	badChecks := checkStateDir(filepath.Join(dir, "nonexistent"))
	if len(badChecks) == 0 || badChecks[0].Status != StatusFail {
		t.Errorf("expected StatusFail for nonexistent dir")
	}
}

func TestDoctorReportOutput(t *testing.T) {
	rep := DoctorReport{
		Summary: "OK (all passed)",
		Checks: []CheckResult{
			{
				Category: "TestCategory",
				Name:     "TestCheck",
				Status:   StatusOK,
				Message:  "Everything looks good",
			},
		},
		Passed: 1,
	}

	var humanBuf bytes.Buffer
	PrintHumanReport(&humanBuf, rep)
	if !strings.Contains(humanBuf.String(), "TestCategory") || !strings.Contains(humanBuf.String(), "Everything looks good") {
		t.Errorf("Human output missing check info: %s", humanBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := PrintJSONReport(&jsonBuf, rep); err != nil {
		t.Fatalf("PrintJSONReport error: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"TestCategory"`) {
		t.Errorf("JSON output missing check info: %s", jsonBuf.String())
	}
}

func TestRunDoctorBasic(t *testing.T) {
	dir := t.TempDir()
	opts := DoctorOptions{
		StateDir: dir,
		EnvFile:  filepath.Join(dir, "easy-waf.env"),
	}

	_ = os.WriteFile(opts.EnvFile, []byte("DATABASE_URL=\n"), 0o600)
	rep := RunDoctor(context.Background(), opts)

	if len(rep.Checks) == 0 {
		t.Fatal("expected diagnostic checks to be executed")
	}
}
