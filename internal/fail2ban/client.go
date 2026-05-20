package fail2ban

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var jailNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// CommandRunner runs fail2ban-client (or sudo wrapper). Tests inject a fake runner.
type CommandRunner func(ctx context.Context, bin string, args ...string) ([]byte, error)

// Client wraps fail2ban-client for status and unban operations.
type Client struct {
	Bin     string
	UseSudo bool
	Run     CommandRunner
}

// Status is a lightweight integration snapshot for the UI.
type Status struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Message   string `json:"message,omitempty"`
}

// JailSummary lists banned IPs for one jail.
type JailSummary struct {
	Name      string   `json:"name"`
	BannedIPs []string `json:"banned_ips"`
}

// Overview is returned by GET /integrations/fail2ban.
type Overview struct {
	Status Status        `json:"status"`
	Jails  []JailSummary `json:"jails"`
}

// DefaultClient returns a client with distro paths and optional sudo (EASY_WAF_FAIL2BAN_USE_SUDO=1).
func DefaultClient() *Client {
	return &Client{
		Bin:     resolveBin(),
		UseSudo: strings.TrimSpace(os.Getenv("EASY_WAF_FAIL2BAN_USE_SUDO")) == "1",
		Run:     execRunner,
	}
}

func resolveBin() string {
	for _, p := range []string{"/usr/bin/fail2ban-client", "/bin/fail2ban-client", "fail2ban-client"} {
		if p == "fail2ban-client" {
			if lp, err := exec.LookPath(p); err == nil {
				return lp
			}
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/fail2ban-client"
}

func execRunner(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	return cmd.CombinedOutput()
}

// Ping checks whether the fail2ban daemon responds.
func (c *Client) Ping(ctx context.Context) Status {
	out, err := c.run(ctx, "ping")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		low := strings.ToLower(msg)
		if strings.Contains(low, "not found") || strings.Contains(low, "no such file") {
			return Status{Message: ErrNotInstalled.Error()}
		}
		return Status{Installed: true, Running: false, Message: msg}
	}
	if strings.Contains(strings.ToLower(string(out)), "pong") {
		return Status{Installed: true, Running: true, Message: "pong"}
	}
	return Status{Installed: true, Running: false, Message: strings.TrimSpace(string(out))}
}

// Overview collects global status and per-jail banned IP lists.
func (c *Client) Overview(ctx context.Context) (Overview, error) {
	st := c.Ping(ctx)
	if !st.Installed && strings.Contains(st.Message, "not found") {
		return Overview{Status: st}, ErrNotInstalled
	}
	if !st.Running {
		return Overview{Status: st}, nil
	}
	out, err := c.run(ctx, "status")
	if err != nil {
		st.Message = strings.TrimSpace(string(out))
		return Overview{Status: st}, err
	}
	names := parseStatusJails(string(out))
	jails := make([]JailSummary, 0, len(names))
	for _, name := range names {
		js, err := c.JailStatus(ctx, name)
		if err != nil {
			js = JailSummary{Name: name, BannedIPs: nil}
		}
		jails = append(jails, js)
	}
	return Overview{Status: st, Jails: jails}, nil
}

// JailStatus returns banned IPs for one jail.
func (c *Client) JailStatus(ctx context.Context, jail string) (JailSummary, error) {
	jail = strings.TrimSpace(jail)
	if !validJailName(jail) {
		return JailSummary{}, ErrInvalidJail
	}
	out, err := c.run(ctx, "status", jail)
	if err != nil {
		return JailSummary{Name: jail}, fmt.Errorf("fail2ban status %s: %w: %s", jail, err, strings.TrimSpace(string(out)))
	}
	return JailSummary{Name: jail, BannedIPs: parseJailBannedIPs(string(out))}, nil
}

// UnbanIP removes one IP from a jail ban list.
func (c *Client) UnbanIP(ctx context.Context, jail, ip string) error {
	jail = strings.TrimSpace(jail)
	ip = strings.TrimSpace(ip)
	if !validJailName(jail) {
		return ErrInvalidJail
	}
	if net.ParseIP(ip) == nil {
		return ErrInvalidIP
	}
	out, err := c.run(ctx, "set", jail, "unbanip", ip)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("fail2ban unban: %s", msg)
	}
	return nil
}

func (c *Client) run(ctx context.Context, args ...string) ([]byte, error) {
	run := c.Run
	if run == nil {
		run = execRunner
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	bin := c.Bin
	if bin == "" {
		bin = resolveBin()
	}
	out, err := run(ctx, bin, args...)
	if err == nil {
		return out, nil
	}
	// Auto-sudo is not used: easy-waf-api runs with NoNewPrivileges (sudo cannot elevate).
	// Appliance access is via fail2ban group + socket permissions (install_fail2ban_api_access).
	low := strings.ToLower(string(out) + err.Error())
	if c.UseSudo && needsSudo(low) && !sudoBlockedByNoNewPrivileges(low) {
		sudoOut, sudoErr := run(ctx, "/usr/bin/sudo", append([]string{"-n", bin}, args...)...)
		if sudoErr == nil {
			return sudoOut, nil
		}
		if len(sudoOut) > 0 {
			out = append(out, sudoOut...)
		}
		err = sudoErr
	}
	return out, err
}

// sudoBlockedByNoNewPrivileges detects systemd NoNewPrivileges (easy-waf-api cannot use sudo).
func sudoBlockedByNoNewPrivileges(msg string) bool {
	return strings.Contains(msg, "no new privileges")
}

func needsSudo(msg string) bool {
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "not allowed") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "you must be root")
}

func validJailName(jail string) bool {
	return jail != "" && jailNameRE.MatchString(jail)
}
