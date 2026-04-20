package metrics

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// sampleStatsCSV is a fixed HAProxy "show stat" style CSV (column names match HAProxy native "show stat").
const sampleStatsCSV = `# pxname,svname,scur,smax,status,bin,bout,type,rate,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other
fe_http,FRONTEND,1,10,OPEN,2000,3000,0,5,0,900,50,15,5,0
fe_https,FRONTEND,2,20,OPEN,4000,6000,0,12,0,1800,100,25,15,0
bk_acme,BACKEND,0,5,UP,100,200,1,0,0,45,5,0,0,0
bk_acme,s1,0,1,UP,50,75,2,0,0,20,5,0,0,0
bk_ha_example_com,BACKEND,1,3,UP,200,300,1,1,0,80,15,3,2,0
bk_ha_example_com,s1,1,2,UP,150,250,2,1,0,70,8,2,0,0
bk_ha_example_com,s2,0,0,DOWN,0,0,2,0,0,0,0,0,0,0
`

func TestParseShowStatCSV(t *testing.T) {
	rep, err := ParseShowStatCSV([]byte(sampleStatsCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Frontends) != 2 {
		t.Fatalf("frontends: got %d want 2", len(rep.Frontends))
	}
	if rep.Frontends[0].Name != "fe_http" || rep.Frontends[0].ReqRate != 5 || rep.Frontends[0].SessionsCur != 1 {
		t.Fatalf("fe_http: %+v", rep.Frontends[0])
	}
	if rep.Frontends[1].HTTP4xx != 25 || rep.Frontends[1].HTTP5xx != 15 {
		t.Fatalf("fe_https 4xx/5xx: %+v", rep.Frontends[1])
	}
	if len(rep.Backends) != 2 {
		t.Fatalf("backends: got %d want 2", len(rep.Backends))
	}
	if rep.Backends[1].Name != "bk_ha_example_com" || rep.Backends[1].Health != "degraded" {
		t.Fatalf("backend health: %+v", rep.Backends[1])
	}
	if len(rep.Backends[1].Servers) != 2 {
		t.Fatalf("servers: %d", len(rep.Backends[1].Servers))
	}

	sum := BuildSummary(rep)
	if sum.ActiveSessions != 3 {
		t.Fatalf("active_sessions: got %d want 3", sum.ActiveSessions)
	}
	if sum.ReqRate != 17 {
		t.Fatalf("req_rate: got %v want 17", sum.ReqRate)
	}
	// blocked = fe_https 4xx+5xx only
	if sum.BlockedRequests != 40 {
		t.Fatalf("blocked_requests: got %d want 40", sum.BlockedRequests)
	}
	if sum.BackendsUp != 2 || sum.BackendsDown != 1 {
		t.Fatalf("backend server counts: up=%d down=%d", sum.BackendsUp, sum.BackendsDown)
	}
}

func TestStatsSocketPath(t *testing.T) {
	gs := config.GlobalSettings{HAProxyStatsSocketPath: "/custom.sock"}
	if p := StatsSocketPath(gs, "/var/lib/easy-waf"); p != "/custom.sock" {
		t.Fatal(p)
	}
	gs2 := config.GlobalSettings{}
	if p := StatsSocketPath(gs2, "/st"); p != "/run/haproxy/easy-waf-admin.sock" {
		t.Fatal(p)
	}
	gs3 := config.GlobalSettings{HAProxyStatsSocketPath: "/var/lib/easy-waf/haproxy/admin.sock"}
	if p := StatsSocketPath(gs3, "/var/lib/easy-waf"); p != "/run/haproxy/easy-waf-admin.sock" {
		t.Fatalf("legacy state socket migrates to /run: got %q", p)
	}
}
