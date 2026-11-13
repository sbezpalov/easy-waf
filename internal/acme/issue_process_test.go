// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/easy-waf/easy-waf/internal/commandoutput"
	"github.com/easy-waf/easy-waf/internal/commandprocess"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--issue-parent-test" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = IssueInProcess(ctx, executable, IssueRequest{Email: "ops@example.test", Domains: []string{"example.test"}, Mode: "http-01", WebrootPath: os.Getenv("EASY_WAF_ACME_TEST_CA_URL")})
		cancel()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == IssueChildArg {
		mode := os.Getenv("EASY_WAF_ACME_PROCESS_TEST")
		if mode == "malformed" || mode == "oversized" || mode == "crash" {
			if mode == "crash" {
				os.Exit(9)
			}
			text := "PRIVATE-TEST-MARKER"
			if mode == "oversized" {
				text = strings.Repeat(text, commandoutput.Limit/len(text)+1)
			}
			_, _ = io.WriteString(os.Stdout, text)
			os.Exit(0)
		}
		if mode == "duplicate" || mode == "casefold" || mode == "contradictory" || mode == "nonzero-success" || mode == "trailing" {
			res, err := issueTestResource()
			if err != nil {
				os.Exit(2)
			}
			ok := true
			response := issueWireResponse{Version: 1, OK: &ok, Result: &issueWireResource{
				Domain: res.Domain, Certificate: res.Certificate, PrivateKey: res.PrivateKey}}
			if mode == "contradictory" {
				response.Error = "fixture failure"
			}
			body, _ := json.Marshal(response)
			switch mode {
			case "duplicate":
				body = bytes.Replace(body, []byte(`"ok":true`), []byte(`"ok":true,"ok":true`), 1)
			case "casefold":
				body = bytes.Replace(body, []byte(`"ok":true`), []byte(`"OK":true`), 1)
			case "trailing":
				body = append(body, []byte(` {"version":1}`)...)
			}
			_, _ = os.Stdout.Write(body)
			if mode == "nonzero-success" {
				os.Exit(7)
			}
			os.Exit(0)
		}
		os.Exit(serveIssueChild(os.Stdin, os.Stdout, func(_ context.Context, request IssueRequest) (*certificate.Resource, error) {
			if os.Getenv("DATABASE_URL") != "" || os.Getenv("EASY_WAF_JWT_SECRET") != "" || os.Getenv("EASY_WAF_ADMIN_TOKEN") != "" {
				return nil, errors.New("child inherited control-plane credentials")
			}
			switch mode {
			case "mock-ca":
				client, err := issueTestClient(request.WebrootPath)
				if err != nil {
					return nil, err
				}
				return client.Certificate.Obtain(certificate.ObtainRequest{Domains: request.Domains})
			case "block":
				if ready := os.Getenv("EASY_WAF_ACME_TEST_READY"); ready != "" {
					_ = os.WriteFile(ready, []byte("ready"), 0o600)
				}
				time.Sleep(time.Hour) // Deliberately ignores ctx, like an SDK wait.
			case "failure":
				return nil, errors.New("fixture DNS failure")
			case "environment":
				cleanup, err := ApplyEnvFromFile(request.DNSCredentialsEnvFile)
				if err != nil {
					return nil, err
				}
				defer cleanup()
			}
			res, err := issueTestResource()
			if err == nil && mode == "environment" {
				res.CertURL = os.Getenv("EASY_WAF_ACME_ENV_SCOPE")
			}
			if err == nil && mode == "invalid-pair" {
				res.PrivateKey = []byte("PRIVATE-TEST-MARKER")
			}
			return res, err
		}))
	}
	os.Exit(m.Run())
}

func issueTestResource() (*certificate.Resource, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"},
		DNSNames: []string{"example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &certificate.Resource{Domain: "example.test", Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}, nil
}

func issueTestClient(base string) (*lego.Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(&LegoUser{Email: "ops@example.test", key: key, Registration: &registration.Resource{URI: base + "/account"}})
	cfg.CADirURL = base + "/directory"
	root, err := os.ReadFile(os.Getenv("EASY_WAF_ACME_TEST_CA"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, errors.New("invalid mock CA trust root")
	}
	cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	return lego.NewClient(cfg)
}

func mockIssueCA(t *testing.T) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/account", "newOrder": server.URL + "/order"})
		case "/nonce":
			w.Header().Set("Replay-Nonce", "bm9uY2U")
			w.WriteHeader(http.StatusOK)
		case "/order":
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			close(entered)
			select {
			case <-r.Context().Done():
				close(canceled)
			case <-release:
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	rootPath := filepath.Join(t.TempDir(), "mock-ca.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_ACME_TEST_CA", rootPath)
	t.Cleanup(server.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	return server.URL, entered, canceled
}

func TestObtainCancellationClosesTheActualCARequest(t *testing.T) {
	serverURL, entered, canceled := mockIssueCA(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_ACME_PROCESS_TEST", "mock-ca")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := IssueInProcess(ctx, executable, IssueRequest{Email: "ops@example.test", Domains: []string{"example.test"}, Mode: "http-01", WebrootPath: serverURL})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("mock CA order was not reached")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause lost: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attempt did not finish after cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("attempt returned while its real CA request remained alive")
	}
}

func TestParentDeathClosesTheActualCARequest(t *testing.T) {
	serverURL, entered, canceled := mockIssueCA(t)
	t.Setenv("EASY_WAF_ACME_PROCESS_TEST", "mock-ca")
	t.Setenv("EASY_WAF_ACME_TEST_CA_URL", serverURL)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "--issue-parent-test")
	commandprocess.Prepare(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		cancel()
		_ = commandprocess.Finish(cmd, true)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("test supervisor was not reaped")
		}
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("child did not reach the real SDK order request")
	}
	// Kill only the tracked parent, not its separately grouped attempt child.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("test supervisor did not exit")
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("CA request survived the death of its parent owner")
	}
}

func TestIssueProcessResultAndEnvironmentIsolation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := IssueRequest{Email: "ops@example.test", Domains: []string{"example.test"}, Mode: "http-01"}
	for _, mode := range []string{"success", "environment", "failure", "malformed", "oversized", "crash", "invalid-pair", "duplicate", "casefold", "contradictory", "nonzero-success", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("EASY_WAF_ACME_PROCESS_TEST", mode)
			t.Setenv("EASY_WAF_ACME_ENV_SCOPE", "parent")
			t.Setenv("DATABASE_URL", "PRIVATE-TEST-MARKER")
			t.Setenv("EASY_WAF_JWT_SECRET", "PRIVATE-TEST-MARKER")
			t.Setenv("EASY_WAF_ADMIN_TOKEN", "PRIVATE-TEST-MARKER")
			file := filepath.Join(t.TempDir(), "credentials")
			if err := os.WriteFile(file, []byte("EASY_WAF_ACME_ENV_SCOPE=child\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			request.DNSCredentialsEnvFile = file
			res, err := IssueInProcess(t.Context(), executable, request)
			if mode == "success" || mode == "environment" {
				if err != nil || res == nil || res.Domain != "example.test" || len(res.PrivateKey) == 0 {
					t.Fatalf("successful resource was not preserved: %v", err)
				}
				if mode == "environment" && res.CertURL != "child" {
					t.Fatal("child did not receive its credentials environment")
				}
			} else if err == nil || res != nil || strings.Contains(err.Error(), "PRIVATE-TEST-MARKER") {
				t.Fatal("failed/incomplete result accepted or raw private output exposed")
			}
			if os.Getenv("EASY_WAF_ACME_ENV_SCOPE") != "parent" {
				t.Fatal("issuance changed the parent environment")
			}
		})
	}
}

func TestIssueChildEnvironmentFiltersAliasesWithoutChangingProviderOptions(t *testing.T) {
	got := issueChildEnvironment([]string{"DATABASE_URL=private", "database_url=private", "EASY_WAF_JWT_SECRET=private",
		"easy_waf_admin_token=private", "AWS_REGION=region", "LEGO_CA_CERTIFICATES=roots", "PATH=tools"})
	if strings.Join(got, "|") != "AWS_REGION=region|LEGO_CA_CERTIFICATES=roots|PATH=tools" {
		t.Fatal("control-plane credential alias inherited or required SDK environment lost")
	}
}

func TestIssueChildSelfDeadlineAndSignalGrace(t *testing.T) {
	for _, secondSignal := range []bool{false, true} {
		t.Run(fmt.Sprint(secondSignal), func(t *testing.T) {
			if secondSignal && runtime.GOOS == "windows" {
				t.Skip("POSIX service-signal semantics")
			}
			t.Setenv("EASY_WAF_ACME_PROCESS_TEST", "block")
			ready := filepath.Join(t.TempDir(), "ready")
			t.Setenv("EASY_WAF_ACME_TEST_READY", ready)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			budget := time.Second
			if secondSignal {
				budget = 2 * time.Second
			}
			body, _ := json.Marshal(issueWireRequest{Version: 1, Deadline: time.Now().Add(budget), Request: IssueRequest{Email: "ops@example.test", Domains: []string{"example.test"}}})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, IssueChildArg)
			commandprocess.Prepare(cmd)
			input, owner, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = input.Close(); _ = owner.Close() })
			cmd.Stdin = input
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = input.Close()
			if _, err := owner.Write(append(body, '\n')); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			reaped := make(chan struct{})
			go func() { done <- cmd.Wait(); close(reaped) }()
			t.Cleanup(func() {
				cancel()
				_ = commandprocess.Finish(cmd, true)
				select {
				case <-reaped:
				case <-time.After(2 * time.Second):
					t.Error("test child was not reaped")
				}
			})
			if secondSignal {
				until := time.Now().Add(2 * time.Second)
				for {
					if _, err := os.Stat(ready); err == nil {
						break
					}
					if time.Now().After(until) {
						t.Fatal("child did not enter the SDK wait")
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					t.Fatalf("first service TERM abandoned issuance: %v", err)
				case <-time.After(30 * time.Millisecond):
				}
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				var exit *exec.ExitError
				if !errors.As(err, &exit) || (!secondSignal && exit.ExitCode() != issueTimeoutExit) || (secondSignal && exit.ExitCode() != -1) || ctx.Err() != nil {
					t.Fatalf("self deadline/second signal did not terminate independently: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("child outlived its own deadline/signal")
			}
		})
	}
}

func TestIssueProcessCancellationAndRequestBudget(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := IssueRequest{Email: "ops@example.test", Domains: []string{"example.test"}, Mode: "http-01"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if res, err := IssueInProcess(ctx, executable, request); res != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled request launched or lost its cause")
	}
	request.WebrootPath = strings.Repeat("PRIVATE-TEST-MARKER", maxIssueRequest)
	if res, err := IssueInProcess(t.Context(), executable, request); res != nil || err == nil || !strings.Contains(err.Error(), "budget") || strings.Contains(err.Error(), "PRIVATE-TEST-MARKER") {
		t.Fatal("oversized request was launched or echoed")
	}
	request.WebrootPath = ""
	t.Setenv("EASY_WAF_ACME_PROCESS_TEST", "block")
	ctx, cancel = context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	started := time.Now()
	res, err := IssueInProcess(ctx, executable, request)
	if res != nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "cleanup may be incomplete") || time.Since(started) > 4*time.Second {
		t.Fatalf("noncooperative child outlived parent deadline or claimed a known outcome: %v", err)
	}
}

func TestIssueProcessAcceptsExactRequestBudgetWithoutLosingOwner(t *testing.T) {
	t.Setenv("EASY_WAF_ACME_PROCESS_TEST", "success")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	request := IssueRequest{Email: "ops@example.test", Domains: []string{"example.test"}, Mode: "http-01"}
	body, err := json.Marshal(issueWireRequest{Version: 1, Deadline: deadline, Request: request})
	if err != nil {
		t.Fatal(err)
	}
	request.WebrootPath = strings.Repeat("x", maxIssueRequest-len(body))
	res, err := IssueInProcess(ctx, executable, request)
	if err != nil || res == nil {
		t.Fatalf("exact 64 KiB request confused the framing limit with owner EOF: %v", err)
	}
	request.WebrootPath += "x"
	if res, err := IssueInProcess(ctx, executable, request); res != nil || err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatal("first byte over the request budget was launched")
	}
}

func TestIssueChildRejectsInvalidRequestsBeforeIssuance(t *testing.T) {
	for _, body := range []string{
		"", "null", "[]", `{"version":1}`, `{"version":null}`, `{"Version":1}`,
		`{"version":1,"version":1}`, `{"version":1} {"version":1}`,
		`{"version":1,"deadline":"2026-01-01T00:00:00Z","request":{"email":"ops@example.test","domains":["example.test"]}}`,
		strings.Repeat("x", maxIssueRequest+1),
	} {
		calls := 0
		var output bytes.Buffer
		code := serveIssueChild(strings.NewReader(body+"\n"), &output, func(context.Context, IssueRequest) (*certificate.Resource, error) {
			calls++
			return nil, errors.New("unexpected issue")
		})
		var result issueWireResponse
		if code == 0 || calls != 0 || decodeIssueJSON(output.Bytes(), &result) != nil || result.OK == nil || *result.OK || result.Result != nil {
			t.Fatal("invalid/expired child request reached the CA or became success")
		}
	}
}

func TestDirectIssuancePreCanceledDoesNotTouchFilesOrEnvironment(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dir := t.TempDir()
	webroot, account := filepath.Join(dir, "webroot"), filepath.Join(dir, "account.pem")
	if _, err := IssueHTTP01Webroot(ctx, "ops@example.test", []string{"example.test"}, webroot, true, account); !errors.Is(err, context.Canceled) {
		t.Fatal("HTTP setup ignored cancellation")
	}
	if _, err := os.Stat(webroot); !os.IsNotExist(err) {
		t.Fatal("canceled HTTP setup touched its webroot")
	}
	t.Setenv("EASY_WAF_ACME_ENV_SCOPE", "parent")
	file := filepath.Join(dir, "credentials")
	if err := os.WriteFile(file, []byte("EASY_WAF_ACME_ENV_SCOPE=child\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := IssueDNS01(ctx, "ops@example.test", []string{"example.test"}, true, account, "webhook", file, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("DNS setup ignored cancellation")
	}
	if os.Getenv("EASY_WAF_ACME_ENV_SCOPE") != "parent" {
		t.Fatal("canceled DNS setup mutated environment")
	}
	if _, err := os.Stat(account); !os.IsNotExist(err) {
		t.Fatal("canceled setup created an account key")
	}
}
