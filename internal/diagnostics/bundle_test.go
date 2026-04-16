package diagnostics

import (
	"context"
	"testing"
)

func TestBuildSupportBundleGzip_nilStore(t *testing.T) {
	_, err := BuildSupportBundleGzip(context.Background(), Params{})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}
