package users

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// Account is a local UNIX account (non-system focus).
type Account struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Home     string   `json:"home"`
	Shell    string   `json:"shell"`
	SSHKeys  []string `json:"ssh_keys,omitempty"`
}

// List parses /etc/passwd for human users (uid >= 1000).
func List() ([]Account, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Account
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid := parts[2]
		uidNum, err := strconv.Atoi(uid)
		if err != nil || (uidNum < 1000 && uidNum != 0) {
			continue
		}
		if parts[0] == "nobody" {
			continue
		}
		ac := Account{
			Username: parts[0],
			UID:      uid,
			Home:     parts[5],
			Shell:    parts[6],
		}
		ac.SSHKeys = readAuthorizedKeys(ac.Home)
		out = append(out, ac)
	}
	return out, sc.Err()
}

func readAuthorizedKeys(home string) []string {
	path := home + "/.ssh/authorized_keys"
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var keys []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys
}

// CreateUser adds a login user.
func CreateUser(ctx context.Context, username string) error {
	if !hostspec.ManageableUsername(username) {
		return fmt.Errorf("user is protected")
	}
	_, err := runner.Privileged(ctx, "useradd", username)
	return err
}

// DeleteUser removes a login user.
func DeleteUser(ctx context.Context, username string) error {
	if !hostspec.ManageableUsername(username) {
		return fmt.Errorf("user is protected")
	}
	_, err := runner.Privileged(ctx, "userdel", username)
	return err
}

// SetSSHKeys replaces authorized_keys for the user.
func SetSSHKeys(ctx context.Context, username string, keys []string) error {
	if !hostspec.ManageableUsername(username) {
		return fmt.Errorf("user is protected")
	}
	if err := ValidateSSHPublicKeys(keys); err != nil {
		return err
	}
	dir := "/var/lib/easy-waf/staging"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := dir + "/authorized_keys-" + username
	var b strings.Builder
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		b.WriteString(k)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	_, err := runner.Privileged(ctx, "ssh-authorized-keys", username, path)
	return err
}
