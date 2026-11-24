// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/blocklog"
	"github.com/easy-waf/easy-waf/internal/commandoutput"
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

type mockRunner struct {
	lastName string
	lastArgs []string
	err      error
}

func TestDispatchTimezoneSet(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want []string
		ok   bool
	}{
		{argv: []string{"timezone-set"}},
		{argv: []string{"timezone-set", "Europe/Amsterdam", "UTC"}},
		{argv: []string{"timezone-set", "--help"}},
		{argv: []string{"timezone-set", "Europe/../UTC"}},
		{argv: []string{"timezone-set", "Unknown/City"}, want: []string{"list-timezones"}},
		{argv: []string{"timezone-set", "Europe/Amsterdam"}, want: []string{"list-timezones", "set-timezone Europe/Amsterdam"}, ok: true},
	} {
		var calls []string
		r := packageRestartRunner(func(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
			if name != hostspec.TimedatectlPath {
				t.Fatalf("unexpected program %q", name)
			}
			calls = append(calls, strings.Join(args, " "))
			return []byte("Etc/UTC\nEurope/Amsterdam\n"), nil, 0, nil
		})
		got := (&Dispatcher{Runner: r}).Dispatch(t.Context(), tc.argv)
		if got.OK != tc.ok || !slices.Equal(calls, tc.want) {
			t.Errorf("%q: response %+v, calls %q, want success=%v and calls %q", tc.argv, got, calls, tc.ok, tc.want)
		}
	}
}

func (m *mockRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	m.lastName = name
	m.lastArgs = args
	if name == binSystemctl && len(args) >= 2 && args[0] == "reboot" {
		return nil, nil, 0, nil
	}
	if name == binNft {
		return []byte("table inet x\n"), nil, 0, nil
	}
	return []byte("ok"), nil, 0, m.err
}

func TestDispatch_unknownOp(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"evil-cmd"})
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(r.Error, "unknown") {
		t.Fatalf("got %q", r.Error)
	}
}

func TestDispatch_systemctlReject(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"systemctl", "mask", "ssh.service"})
	if r.OK {
		t.Fatal("ssh not allowed")
	}
	r = d.Dispatch(context.Background(), []string{"systemctl", "restart", "haproxy.service"})
	if !r.OK {
		t.Fatalf("haproxy restart: %v", r.Error)
	}
}

func TestDispatch_userdelRoot(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"userdel", "root"})
	if r.OK {
		t.Fatal("root protected")
	}
}

func TestDispatch_nftList(t *testing.T) {
	m := &mockRunner{}
	d := &Dispatcher{Runner: m}
	r := d.Dispatch(context.Background(), []string{"nft-list"})
	if !r.OK {
		t.Fatal(r.Error)
	}
	if m.lastName != "/usr/sbin/nft" || m.lastArgs[0] != "list" {
		t.Fatalf("got %s %v", m.lastName, m.lastArgs)
	}
}

func TestDispatch_invalidStagedPath(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"netplan-apply-confirm", "/etc/passwd", "90", "abcdef0123456789abcdef0123456789"})
	if r.OK {
		t.Fatal("path rejected")
	}
}

func TestDispatch_journalBadFlag(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	for _, flag := range []string{"--follow", "--output-fields=MESSAGE"} {
		r := d.Dispatch(t.Context(), []string{"journal", "-u", "haproxy.service", flag})
		if r.OK {
			t.Errorf("accepted caller-supplied %s", flag)
		}
	}
}

func TestDispatchJournalReportsOutputLimit(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{err: commandoutput.ErrLimit}}
	resp := d.Dispatch(t.Context(), []string{"journal", "-n", "5000", "-u", "haproxy.service", "--output", "json"})
	if resp.OK || !resp.OutputLimited || resp.Error != commandoutput.ErrLimit.Error() {
		t.Fatalf("unexpected broker response: %+v", resp)
	}
}

func TestDispatchJournalProjectsFieldsForStructuredHAProxyEvents(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		selected bool
	}{
		{"blocked requests", []string{"-u", "haproxy.service", "--grep", blocklog.JournalGrepBlocked, "--output", "json"}, true},
		{"publication rules", []string{"--output", "json", "--grep", blocklog.JournalGrepPolicy, "-u", "haproxy.service"}, true},
		{"legacy edge query", []string{"-u", "haproxy", "--grep", "[PL]R--", "--output", "json"}, true},
		{"service snapshot", []string{"-u", "haproxy.service", "--output", "json"}, false},
		{"text output", []string{"-u", "haproxy.service", "--grep", blocklog.JournalGrepBlocked, "--output", "cat"}, false},
		{"multiple units", []string{"-u", "haproxy.service", "-u", "crowdsec.service", "--grep", blocklog.JournalGrepPolicy, "--output", "json"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &mockRunner{}
			dispatcher := &Dispatcher{Runner: runner}
			resp := dispatcher.Dispatch(t.Context(), append([]string{"journal"}, tc.args...))
			if !resp.OK || runner.lastName != binJournalctl {
				t.Fatalf("journal dispatch failed: %+v", resp)
			}
			want := slices.Clone(tc.args)
			if tc.selected {
				want = append(want, "--output-fields=MESSAGE")
			}
			if !slices.Equal(runner.lastArgs, want) {
				t.Fatalf("journalctl argv = %v, want %v", runner.lastArgs, want)
			}
		})
	}
}

func TestDispatch_fail2banReject(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	for _, argv := range [][]string{
		{"fail2ban", "reload"},
		{"fail2ban", "set", "sshd", "banip", "1.2.3.4"},
		{"fail2ban", "status", "../evil"},
		{"fail2ban", "set", "sshd", "unbanip", "not-ip"},
	} {
		r := d.Dispatch(context.Background(), argv)
		if r.OK {
			t.Fatalf("expected reject: %v", argv)
		}
		if !strings.Contains(r.Error, "not allowed") {
			t.Fatalf("%v: %q", argv, r.Error)
		}
	}
}

func TestDispatch_fail2banAllowed(t *testing.T) {
	if resolveFail2banClient() == "" {
		t.Skip("fail2ban-client not installed")
	}
	m := &mockRunner{}
	d := &Dispatcher{Runner: m}
	for _, argv := range [][]string{
		{"fail2ban", "ping"},
		{"fail2ban", "status"},
		{"fail2ban", "status", "sshd"},
		{"fail2ban", "set", "sshd", "unbanip", "203.0.113.1"},
	} {
		r := d.Dispatch(context.Background(), argv)
		if !r.OK {
			t.Fatalf("%v: %s", argv, r.Error)
		}
		if m.lastName == "" {
			t.Fatalf("%v: runner not called", argv)
		}
	}
}
