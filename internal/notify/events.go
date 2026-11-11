// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// Severity values of Event.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Event is one operational notification. It carries no secret.
type Event struct {
	Kind     string `json:"event"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Text     string `json:"text"`
}

type eventPayload struct {
	Source string    `json:"source"`
	Host   string    `json:"host,omitempty"`
	Time   time.Time `json:"time"`
	Event
}

// telegramAPI is replaced in tests.
var telegramAPI = "https://api.telegram.org"

const telegramMaxText = 4000

// TelegramEnabled reports whether both the chat and the bot token are set.
func TelegramEnabled(gs config.GlobalSettings) bool {
	return strings.TrimSpace(gs.NotifyTelegramChatID) != "" && strings.TrimSpace(gs.NotifyTelegramBotToken) != ""
}

// Enabled reports whether any notification channel is configured.
func Enabled(gs config.GlobalSettings) bool {
	return strings.TrimSpace(gs.NotifyWebhookURL) != "" || TelegramEnabled(gs)
}

// Send delivers ev to every configured channel: the webhook gets JSON, Telegram
// a text message. One failing channel does not stop the other.
func Send(ctx context.Context, gs config.GlobalSettings, ev Event) error {
	host, _ := os.Hostname()
	var errs []error
	if raw := strings.TrimSpace(gs.NotifyWebhookURL); raw != "" {
		body, err := json.Marshal(eventPayload{Source: "easy-waf", Host: host, Time: time.Now().UTC(), Event: ev})
		if err == nil {
			err = postJSON(ctx, raw, body, "easy-waf")
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if TelegramEnabled(gs) {
		if err := sendTelegram(ctx, gs, telegramText(host, ev)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SendTelegram delivers ev to Telegram only, when it is configured.
func SendTelegram(ctx context.Context, gs config.GlobalSettings, ev Event) error {
	if !TelegramEnabled(gs) {
		return nil
	}
	host, _ := os.Hostname()
	return sendTelegram(ctx, gs, telegramText(host, ev))
}

// sendTelegram calls the Bot API sendMessage. Errors never contain the token.
func sendTelegram(ctx context.Context, gs config.GlobalSettings, text string) error {
	token := strings.TrimSpace(gs.NotifyTelegramBotToken)
	if err := config.ValidateTelegramBotToken(token); err != nil {
		return errors.New("telegram bot token is not valid")
	}
	body, err := json.Marshal(map[string]any{
		"chat_id":                  strings.TrimSpace(gs.NotifyTelegramChatID),
		"text":                     text,
		"disable_web_page_preview": true,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramAPI+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram request is not usable")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := newClient().Do(req)
	if err != nil {
		if errors.Is(err, errWebhookBlocked) {
			return errors.New("telegram destination is not allowed")
		}
		return errors.New("telegram request failed")
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&out)
	if resp.StatusCode == http.StatusOK && out.OK {
		return nil
	}
	desc := strings.ReplaceAll(out.Description, token, "***")
	if len(desc) > 200 {
		desc = desc[:200]
	}
	if desc == "" {
		return fmt.Errorf("telegram returned HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("telegram returned HTTP %d: %s", resp.StatusCode, desc)
}

func telegramText(host string, ev Event) string {
	prefix := "Easy Home WAF"
	if host != "" {
		prefix += " (" + host + ")"
	}
	s := prefix + ": " + ev.Title
	if ev.Text != "" {
		s += "\n" + ev.Text
	}
	if len(s) > telegramMaxText {
		s = s[:telegramMaxText]
	}
	return s
}

// CertificateEvent summarizes certificate notices for Telegram.
func CertificateEvent(notices []Notice) Event {
	lines := make([]string, 0, len(notices))
	for _, n := range notices {
		l := n.Domain + ": " + n.Attention
		if n.LastError != "" {
			l += " (" + n.LastError + ")"
		}
		lines = append(lines, l)
	}
	return Event{
		Kind:     "certificate_attention",
		Severity: SeverityWarning,
		Title:    fmt.Sprintf("%d certificate(s) need attention", len(notices)),
		Text:     strings.Join(lines, "\n"),
	}
}
