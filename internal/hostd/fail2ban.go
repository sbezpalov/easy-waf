// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"os"
	"os/exec"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

func resolveFail2banClient() string {
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
	return ""
}

func fail2banClientArgs(args []string) ([]string, bool) {
	switch len(args) {
	case 1:
		switch args[0] {
		case "ping", "status":
			return args, true
		}
	case 2:
		if args[0] == "status" && hostspec.ValidJailName(args[1]) {
			return args, true
		}
	case 4:
		if args[0] == "set" && args[2] == "unbanip" &&
			hostspec.ValidJailName(args[1]) && hostspec.ValidIP(args[3]) {
			return args, true
		}
	}
	return nil, false
}

func dispatchFail2ban(ctx context.Context, r CommandRunner, args []string) Response {
	clientArgs, ok := fail2banClientArgs(args)
	if !ok {
		return failResp("fail2ban: command not allowed", 1)
	}
	bin := resolveFail2banClient()
	if bin == "" {
		return failResp("fail2ban-client not found", 127)
	}
	stdout, stderr, code, err := runCmd(ctx, r, bin, clientArgs...)
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	return okResp(stdout, stderr, code)
}
