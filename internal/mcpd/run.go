// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mcpd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
)

// Run serves the opt-in MCP endpoint until ctx is cancelled.
func Run(ctx context.Context) error {
	listen := strings.TrimSpace(os.Getenv("EASY_WAF_MCP_LISTEN"))
	if listen == "" {
		return nil
	}
	addr, err := netip.ParseAddrPort(listen)
	if err != nil || !addr.Addr().Unmap().IsLoopback() || addr.Addr().Zone() != "" || addr.Port() == 0 {
		return fmt.Errorf("EASY_WAF_MCP_LISTEN must be a loopback IP and nonzero port")
	}
	clientToken := auth.LoadStaticToken("EASY_WAF_MCP_TOKEN", 32)
	apiToken := strings.TrimSpace(os.Getenv("EASY_WAF_MCP_API_TOKEN"))
	if !clientToken.Enabled() || len(apiToken) < 32 || clientToken.Matches(apiToken) {
		return fmt.Errorf("EASY_WAF_MCP_TOKEN and EASY_WAF_MCP_API_TOKEN must be distinct and at least 32 characters")
	}
	api, err := newAPIClient(os.Getenv("EASY_WAF_MCP_API_URL"), os.Getenv("EASY_WAF_MCP_API_CA_FILE"), apiToken)
	if err != nil {
		return err
	}
	defer api.http.CloseIdleConnections()
	listener, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler: newHandler(api, clientToken), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	stopped := make(chan error, 1)
	go func() { stopped <- srv.Serve(listener) }()
	log.Printf("easy-waf-mcpd listening on %s", listener.Addr())
	select {
	case err := <-stopped:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return err
		}
		if err := <-stopped; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func newAPIClient(address, caFile, token string) (apiClient, error) {
	if address == "" {
		address = "https://127.0.0.1:8443"
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return apiClient{}, fmt.Errorf("EASY_WAF_MCP_API_URL must be a loopback HTTPS origin")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Unmap().IsLoopback() || ip.Zone() != "" {
		return apiClient{}, fmt.Errorf("EASY_WAF_MCP_API_URL must use a loopback IP")
	}
	if caFile == "" {
		return apiClient{}, fmt.Errorf("EASY_WAF_MCP_API_CA_FILE must name the management TLS trust certificate")
	}
	pem, err := os.ReadFile(caFile) // #nosec G703 -- The path comes from the operator's service environment.
	if err != nil {
		return apiClient{}, fmt.Errorf("read MCP API trust certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return apiClient{}, fmt.Errorf("MCP API trust file contains no PEM certificates")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			IdleConnTimeout: 30 * time.Second, MaxIdleConns: 4,
		},
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return apiClient{baseURL: u.String(), token: token, http: client}, nil
}
