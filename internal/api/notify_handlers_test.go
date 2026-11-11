// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestSettingsResponseHidesTelegramToken(t *testing.T) {
	const token = "123456789:AAEhBP0av28vH1Ra1sm-xZ8qN3KnyBqV5Wc"
	s := &Server{Eng: engine.New("", nil, config.GlobalSettings{NotifyTelegramChatID: "42", NotifyTelegramBotToken: token})}
	rec := httptest.NewRecorder()
	s.getSettings(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil))
	if strings.Contains(rec.Body.String(), token) {
		t.Fatal("token leaked in GET /settings")
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["notify_telegram_bot_token_set"] != true || got["notify_telegram_chat_id"] != "42" {
		t.Fatalf("settings: %v", got)
	}
}

func TestNotifyTestNeedsAChannel(t *testing.T) {
	s := &Server{Eng: engine.New("", nil, config.GlobalSettings{})}
	rec := httptest.NewRecorder()
	s.notifyTest(rec, httptest.NewRequest(http.MethodPost, "/api/v1/notify/test", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}
