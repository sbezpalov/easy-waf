package config

import (
	"fmt"
	"regexp"
)

const maxResourceIDLength = 128

var resourceIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// ValidateResourceID accepts opaque identifiers that are safe as database keys,
// HAProxy identifier inputs, and a single filesystem path component.
func ValidateResourceID(kind, id string) error {
	if id == "" {
		return fmt.Errorf("%s id is empty", kind)
	}
	if len(id) > maxResourceIDLength {
		return fmt.Errorf("%s id is too long (max %d bytes)", kind, maxResourceIDLength)
	}
	if !resourceIDRE.MatchString(id) {
		return fmt.Errorf("%s id contains invalid characters", kind)
	}
	return nil
}
