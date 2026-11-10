// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateNotifyWebhookURL accepts an empty value (notifications off) or an
// absolute http(s) URL. The URL is not fetched here.
func ValidateNotifyWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return errors.New("notify_webhook_url must be an http or https URL")
	}
	return nil
}
