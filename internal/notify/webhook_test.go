// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestNoticesSkipHealthyCertificates(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	soon := now.Add(5 * 24 * time.Hour)
	later := now.Add(80 * 24 * time.Hour)
	got := Notices([]config.Certificate{
		{PrimaryDomain: "fine.example", ACMEStatus: "ready", NotAfter: &later},
		{PrimaryDomain: "soon.example", ACMEStatus: "ready", NotAfter: &soon, LastError: "timeout"},
	}, now)
	if len(got) != 1 || got[0].Domain != "soon.example" || !strings.Contains(got[0].Attention, "expires") {
		t.Fatalf("%#v", got)
	}
}

func TestValidateWebhookURL(t *testing.T) {
	if err := config.ValidateNotifyWebhookURL(""); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateNotifyWebhookURL("https://alerts.example/hook"); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateNotifyWebhookURL("file:///etc/passwd"); err == nil {
		t.Fatal("file URL accepted")
	}
}

func TestWebhookIPBlocked(t *testing.T) {
	if !webhookIPBlocked(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("metadata address allowed")
	}
	if webhookIPBlocked(netip.MustParseAddr("127.0.0.1")) || webhookIPBlocked(netip.MustParseAddr("192.168.1.10")) {
		t.Fatal("loopback or LAN address blocked")
	}
}

func TestPostWebhookDeliversJSONAndHidesTheURL(t *testing.T) {
	const secret = "super-secret-marker"
	var got payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != secret {
			t.Errorf("token not presented to the receiver")
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := PostWebhook(context.Background(), srv.URL+"?token="+secret, []Notice{{
		Domain: "ha.example", Attention: "expires in 3 days",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Event != "certificate_attention" || len(got.Certificates) != 1 || got.Certificates[0].Domain != "ha.example" {
		t.Fatalf("%#v", got)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	bad := PostWebhook(context.Background(), "http://"+addr+"/hook?token="+secret, []Notice{{Domain: "ha.example", Attention: "expired"}})
	if bad == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(bad.Error(), secret) {
		t.Fatalf("error includes the webhook secret: %v", bad)
	}
}

func TestPostWebhookDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusFound)
	}))
	defer srv.Close()
	err := PostWebhook(context.Background(), srv.URL, []Notice{{Domain: "ha.example", Attention: "expired"}})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("%v", err)
	}
}
