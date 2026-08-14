package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContextMeta(t *testing.T) {
	ctx := context.Background()

	m, ok := From(ctx)
	if ok || m.User != "" || m.SourceIP != "" {
		t.Fatalf("expected empty metadata on fresh context, got ok=%v, m=%+v", ok, m)
	}

	expected := Meta{
		User:     "admin",
		SourceIP: "192.168.1.100",
	}

	ctxWithMeta := WithMeta(ctx, expected)
	got, ok := From(ctxWithMeta)
	if !ok {
		t.Fatalf("expected From(ctxWithMeta) to return ok=true")
	}
	if got.User != expected.User || got.SourceIP != expected.SourceIP {
		t.Errorf("got %+v, want %+v", got, expected)
	}
}

func TestClientHost(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "empty",
			remoteAddr: "",
			want:       "",
		},
		{
			name:       "ip:port",
			remoteAddr: "192.168.1.50:54321",
			want:       "192.168.1.50",
		},
		{
			name:       "ipv6:port",
			remoteAddr: "[::1]:12345",
			want:       "::1",
		},
		{
			name:       "bare ip without port",
			remoteAddr: "10.0.0.1",
			want:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if got := ClientHost(req); got != tt.want {
				t.Errorf("ClientHost(%q) = %q; want %q", tt.remoteAddr, got, tt.want)
			}
		})
	}
}
