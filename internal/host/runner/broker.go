package runner

import (
	"os"
	"strings"
)

const defaultBrokerSocket = "/run/easy-waf/hostd.sock"

type brokerRequest struct {
	Argv []string `json:"argv"`
}

type brokerResponse struct {
	OK     bool   `json:"ok"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Code   int    `json:"code"`
	Error  string `json:"error,omitempty"`
}

// BrokerSocket returns the hostd unix socket path.
func BrokerSocket() string {
	if p := strings.TrimSpace(os.Getenv("EASY_WAF_HOSTD_SOCKET")); p != "" {
		return p
	}
	return defaultBrokerSocket
}

// BrokerAvailable reports whether the host privilege broker socket exists.
func BrokerAvailable() bool {
	st, err := os.Stat(BrokerSocket())
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// HelperInstalled is deprecated; use BrokerAvailable.
func HelperInstalled() bool {
	return BrokerAvailable()
}
