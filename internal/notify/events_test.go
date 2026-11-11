// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

const testToken = "123456789:AAEhBP0av28vH1Ra1sm-xZ8qN3KnyBqV5Wc"

func TestSendWebhookAndTelegram(t *testing.T) {
	var hook map[string]any
	var tgPath string
	var tg map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/hook" {
			_ = json.Unmarshal(b, &hook)
			return
		}
		tgPath = r.URL.Path
		_ = json.Unmarshal(b, &tg)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	orig := telegramAPI
	telegramAPI = srv.URL
	t.Cleanup(func() { telegramAPI = orig })

	gs := config.GlobalSettings{NotifyWebhookURL: srv.URL + "/hook", NotifyTelegramChatID: "-1001234", NotifyTelegramBotToken: testToken}
	if !Enabled(gs) || !TelegramEnabled(gs) {
		t.Fatal("channels should be enabled")
	}
	ev := Event{Kind: "backend_down", Severity: SeverityCritical, Title: "Backend down: bk_a", Text: "details"}
	if err := Send(context.Background(), gs, ev); err != nil {
		t.Fatal(err)
	}
	if hook["source"] != "easy-waf" || hook["event"] != "backend_down" || hook["severity"] != "critical" || hook["title"] != ev.Title || hook["time"] == nil {
		t.Fatalf("webhook payload: %v", hook)
	}
	if tgPath != "/bot"+testToken+"/sendMessage" || tg["chat_id"] != "-1001234" {
		t.Fatalf("telegram request: %s %v", tgPath, tg)
	}
	if text, _ := tg["text"].(string); !strings.Contains(text, "Backend down: bk_a\ndetails") {
		t.Fatalf("telegram text: %q", text)
	}
}

func TestTelegramErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found for ` + testToken + `"}`))
	}))
	defer srv.Close()
	orig := telegramAPI
	telegramAPI = srv.URL
	t.Cleanup(func() { telegramAPI = orig })

	gs := config.GlobalSettings{NotifyTelegramChatID: "42", NotifyTelegramBotToken: testToken}
	err := SendTelegram(context.Background(), gs, Event{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "chat not found") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err = %v", err)
	}
	if err := SendTelegram(context.Background(), config.GlobalSettings{}, Event{}); err != nil {
		t.Fatalf("unconfigured Telegram is a no-op: %v", err)
	}
}

func TestCertificateEvent(t *testing.T) {
	ev := CertificateEvent([]Notice{{Domain: "a.example", Attention: "renewal failed", LastError: "dns"}, {Domain: "b.example", Attention: "expires in 5 days"}})
	if ev.Title != "2 certificate(s) need attention" || ev.Text != "a.example: renewal failed (dns)\nb.example: expires in 5 days" {
		t.Fatalf("%+v", ev)
	}
}
