// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hosttime

import (
	"context"
	"errors"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// CurrentTimezone reads systemd's configured zone at request time. Go's
// time.Local may retain the zone that was active when the daemon started.
func CurrentTimezone() string {
	target, _ := os.Readlink("/etc/localtime")
	return timezoneFromLink(target)
}

func timezoneFromLink(target string) string {
	if !path.IsAbs(target) {
		target = path.Join("/etc", target)
	}
	name, ok := strings.CutPrefix(path.Clean(target), "/usr/share/zoneinfo/")
	if !ok || !hostspec.ValidTimezoneName(name) {
		return "UTC"
	}
	return name
}

func ListTimezones(ctx context.Context) ([]string, error) {
	out, err := runner.Run(ctx, 10*time.Second, hostspec.TimedatectlPath, "list-timezones")
	if err != nil {
		return nil, err
	}
	var zones []string
	for name := range strings.FieldsSeq(string(out)) {
		if hostspec.ValidTimezoneName(name) {
			zones = append(zones, name)
		}
	}
	if len(zones) == 0 {
		return nil, errors.New("host returned no time zones")
	}
	slices.Sort(zones)
	return slices.Compact(zones), nil
}

func SetTimezone(ctx context.Context, name string) error {
	_, err := runner.Privileged(ctx, "timezone-set", name)
	return err
}
