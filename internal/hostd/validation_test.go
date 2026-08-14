package hostd

import "testing"

func TestOpenStagedFileRejectsPathOutsideStaging(t *testing.T) {
	if _, err := openStagedFile("/etc/passwd"); err == nil {
		t.Fatal("expected path outside staging to fail")
	}
}

func TestOpenStagedFileRejectsMissingFile(t *testing.T) {
	if _, err := openStagedFile("/var/lib/easy-waf/staging/missing"); err == nil {
		t.Fatal("expected missing file to fail")
	}
}
