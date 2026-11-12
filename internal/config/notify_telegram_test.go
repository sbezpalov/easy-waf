// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestTelegramSettingsPatch(t *testing.T) {
	const token = "123456789:THIS_IS_A_TEST_TOKEN_NOT_A_SECRET_1234"
	gs, err := ApplySettingsJSONPatch(GlobalSettings{}, []byte(`{"notify_telegram_chat_id":"-100123","notify_telegram_bot_token":"`+token+`","notify_blocked_spike_threshold":200}`))
	if err != nil || gs.NotifyTelegramBotToken != token || gs.NotifyTelegramChatID != "-100123" || gs.NotifyBlockedSpikeThreshold != 200 {
		t.Fatalf("%+v %v", gs, err)
	}
	kept, err := ApplySettingsJSONPatch(gs, []byte(`{"notify_telegram_bot_token":""}`))
	if err != nil || kept.NotifyTelegramBotToken != token {
		t.Fatalf("empty token keeps the stored one: %+v %v", kept, err)
	}
	cleared, err := ApplySettingsJSONPatch(gs, []byte(`{"notify_telegram_chat_id":""}`))
	if err != nil || cleared.NotifyTelegramBotToken != "" {
		t.Fatalf("clearing the chat clears the token: %+v %v", cleared, err)
	}
	for _, bad := range []string{
		`{"notify_telegram_bot_token":"123:abc/../x"}`,
		`{"notify_telegram_chat_id":"chat id"}`,
		`{"notify_blocked_spike_threshold":-1}`,
	} {
		if _, err := ApplySettingsJSONPatch(gs, []byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if err := ValidateTelegramChatID("@easy_waf_alerts"); err != nil {
		t.Error(err)
	}
}
