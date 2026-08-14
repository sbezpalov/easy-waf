//go:build !linux

package hostd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

func openStagedFile(path string) (*os.File, error) {
	if !hostspec.ValidStagedPath(path) {
		return nil, fmt.Errorf("invalid staged path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("staged path is not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !hostspec.ValidStagedPath(resolved) {
		return nil, fmt.Errorf("staged file resolves outside staging")
	}
	return os.Open(resolved)
}
