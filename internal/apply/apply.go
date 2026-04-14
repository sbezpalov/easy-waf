package apply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Validate runs `haproxy -c -f path` using haproxyBinary.
func Validate(haproxyBinary, cfgPath string) error {
	cmd := exec.Command(haproxyBinary, "-c", "-f", cfgPath)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("haproxy -c: %w", err)
	}
	return nil
}

// WriteAtomic writes data to path via a temp file in the same directory, then renames.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReloadHAProxy runs `systemctl reload haproxy` when available.
func ReloadHAProxy() error {
	cmd := exec.Command("systemctl", "reload", "haproxy")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl reload haproxy: %w", err)
	}
	return nil
}
