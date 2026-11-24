// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hosttime

import "testing"

func TestTimezoneFromLink(t *testing.T) {
	for _, tc := range []struct{ link, want string }{
		{"/usr/share/zoneinfo/Europe/Amsterdam", "Europe/Amsterdam"},
		{"../usr/share/zoneinfo/Etc/GMT+5", "Etc/GMT+5"},
		{"/usr/share/zoneinfo/../../etc/localtime", "UTC"},
		{"/usr/share/zoneinfo-other/Europe/Amsterdam", "UTC"},
		{"", "UTC"},
	} {
		if got := timezoneFromLink(tc.link); got != tc.want {
			t.Errorf("zone from %q = %q, want %q", tc.link, got, tc.want)
		}
	}
}
