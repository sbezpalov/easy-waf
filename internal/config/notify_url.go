// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	telegramTokenRe = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)
	telegramChatRe  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// ValidateTelegramBotToken accepts a token as BotFather issues it. The token
// goes into the request path, so nothing else is allowed.
func ValidateTelegramBotToken(s string) error {
	if !telegramTokenRe.MatchString(s) {
		return errors.New("notify_telegram_bot_token must look like 123456:ABC... (from @BotFather)")
	}
	return nil
}

// ValidateTelegramChatID accepts an empty value (Telegram off), a numeric chat
// ID or a public @channel name.
func ValidateTelegramChatID(s string) error {
	if s != "" && !telegramChatRe.MatchString(s) {
		return errors.New("notify_telegram_chat_id must be a numeric chat ID or @channel")
	}
	return nil
}

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
