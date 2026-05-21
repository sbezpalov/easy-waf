package users

import (
	"fmt"
	"regexp"
	"strings"
)

var sshAuthorizedKeyLine = regexp.MustCompile(`^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9-]+) [A-Za-z0-9+/=]+( .*)?$`)

// ValidateSSHPublicKeys checks authorized_keys lines before writing.
func ValidateSSHPublicKeys(keys []string) error {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("invalid ssh key: embedded newline")
		}
		if !sshAuthorizedKeyLine.MatchString(k) {
			return fmt.Errorf("invalid ssh key format")
		}
	}
	return nil
}
