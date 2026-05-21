//go:build !unix

package disk

import (
	"fmt"
	"runtime"
)

func statfsMount(path string) (Mount, fsID, error) {
	return Mount{}, fsID{}, fmt.Errorf("disk: statfs not supported on %s (%s)", runtime.GOOS, path)
}
