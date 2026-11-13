// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/easy-waf/easy-waf/internal/commandoutput"
	"github.com/easy-waf/easy-waf/internal/commandprocess"
)

const (
	IssueChildArg       = "--issue-certificate-child"
	IssueProcessTimeout = 45 * time.Minute
	maxIssueRequest     = 64 << 10
	issueTimeoutExit    = 124
	issueOwnerLostExit  = 125
)

// IssueRequest carries paths/options only. DNS credentials stay in their file
// and are loaded in the child, never into the long-lived worker environment.
type IssueRequest struct {
	Email                 string   `json:"email"`
	Domains               []string `json:"domains"`
	Mode                  string   `json:"mode"`
	Staging               bool     `json:"staging"`
	AccountKeyPath        string   `json:"account_key_path"`
	WebrootPath           string   `json:"webroot_path"`
	DNSProvider           string   `json:"dns_provider"`
	DNSCredentialsEnvFile string   `json:"dns_credentials_env_file"`
	DNSResolvers          []string `json:"dns_resolvers,omitempty"`
}

type issueWireRequest struct {
	Version  int          `json:"version"`
	Deadline time.Time    `json:"deadline"`
	Request  IssueRequest `json:"request"`
}

// certificate.Resource excludes PEM fields from JSON. This private DTO includes
// them explicitly; it must never be included in journal/error output.
type issueWireResource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"cert_url"`
	CertStableURL     string `json:"cert_stable_url"`
	PrivateKey        []byte `json:"private_key"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuer_certificate,omitempty"`
	CSR               []byte `json:"csr,omitempty"`
}

type issueWireResponse struct {
	Version int                `json:"version"`
	OK      *bool              `json:"ok"`
	Result  *issueWireResource `json:"result,omitempty"`
	Error   string             `json:"error,omitempty"`
}

// IssueInProcess owns and joins an entire SDK attempt. Cancellation cannot
// leave an Obtain goroutine issuing after the worker releases its claim/env.
func IssueInProcess(ctx context.Context, executable string, request IssueRequest) (*certificate.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, IssueProcessTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	body, err := json.Marshal(issueWireRequest{Version: 1, Deadline: deadline, Request: request})
	if err != nil || len(body) > maxIssueRequest {
		return nil, errors.New("ACME issue request exceeds its protocol budget")
	}
	cmd := exec.CommandContext(ctx, executable, IssueChildArg)
	commandprocess.Prepare(cmd)
	cmd.Env = issueChildEnvironment(os.Environ())
	input, owner, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("ACME control pipe: %w", err)
	}
	defer input.Close()
	defer owner.Close()
	// Keep the writer open through Wait. EOF then identifies parent death,
	// independently of the SDK timeout and without platform-specific PID races.
	cmd.Stdin = input
	var capture commandoutput.Capture
	// Verbose SDK progress is not a result and must not consume the PEM budget
	// or expose credentials. Actionable SDK failures travel in the JSON error.
	cmd.Stdout, cmd.Stderr = capture.Stdout(), io.Discard
	runErr := cmd.Start()
	if runErr == nil {
		_ = input.Close()
		_, writeErr := owner.Write(append(body, '\n'))
		runErr = errors.Join(writeErr, cmd.Wait())
	}
	cleanupErr := commandprocess.Finish(cmd, true)
	stdout, _, captureErr := capture.Result()
	var exit *exec.ExitError
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(runErr, &exit) && exit.ExitCode() == issueTimeoutExit) {
		return nil, fmt.Errorf("ACME attempt timed out; CA/DNS cleanup may be incomplete: %w", errors.Join(context.DeadlineExceeded, runErr, cleanupErr, captureErr))
	}
	if ctx.Err() != nil || cleanupErr != nil || captureErr != nil {
		return nil, fmt.Errorf("ACME attempt interrupted; CA/DNS cleanup may be incomplete: %w", errors.Join(ctx.Err(), runErr, cleanupErr, captureErr))
	}
	if errors.As(runErr, &exit) && exit.ExitCode() == issueOwnerLostExit {
		return nil, fmt.Errorf("ACME attempt lost its owner; CA/DNS cleanup may be incomplete: %w", runErr)
	}
	var response issueWireResponse
	if decodeIssueJSON(stdout, &response) != nil || response.Version != 1 || response.OK == nil {
		return nil, fmt.Errorf("ACME child returned an invalid/incomplete result: %w", errors.Join(runErr, errors.New("invalid result protocol")))
	}
	if !*response.OK {
		if response.Result != nil || response.Error == "" || len(response.Error) > 32<<10 {
			return nil, errors.New("ACME child returned an invalid failure result")
		}
		return nil, fmt.Errorf("ACME issuance failed: %w", errors.Join(errors.New(response.Error), runErr))
	}
	if runErr != nil || response.Error != "" || response.Result == nil {
		return nil, errors.New("ACME child did not complete successfully")
	}
	r := response.Result
	if _, err := tls.X509KeyPair(r.Certificate, r.PrivateKey); err != nil {
		return nil, errors.New("ACME child returned an invalid certificate/key pair")
	}
	return &certificate.Resource{Domain: r.Domain, CertURL: r.CertURL, CertStableURL: r.CertStableURL,
		PrivateKey: r.PrivateKey, Certificate: r.Certificate, IssuerCertificate: r.IssuerCertificate, CSR: r.CSR}, nil
}

func issueChildEnvironment(parent []string) []string {
	env := make([]string, 0, len(parent))
	for _, entry := range parent {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "DATABASE_URL") || strings.EqualFold(key, "EASY_WAF_JWT_SECRET") || strings.EqualFold(key, "EASY_WAF_ADMIN_TOKEN") {
			continue
		}
		env = append(env, entry)
	}
	// In particular, an older acmed binary that ignores the private argument
	// must fail its required-DSN check, not start another database worker.
	return env
}

func decodeIssueJSON(body []byte, target any) error {
	if !utf8.Valid(body) {
		return errors.New("invalid issue protocol UTF-8")
	}
	check := json.NewDecoder(bytes.NewReader(body))
	if err := checkIssueValue(check, 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid issue protocol JSON")
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return errors.New("trailing issue protocol data")
	}
	return nil
}

func checkIssueValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("issue protocol nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return errors.New("invalid/null issue protocol value")
	}
	delim, object := token.(json.Delim)
	if !object {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			token, err := d.Token()
			if err != nil {
				return errors.New("invalid issue protocol field")
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return errors.New("duplicate/invalid issue protocol field")
			}
			switch key {
			case "version", "deadline", "request", "email", "domains", "mode", "staging", "account_key_path", "webroot_path", "dns_provider", "dns_credentials_env_file", "dns_resolvers",
				"ok", "result", "error", "domain", "cert_url", "cert_stable_url", "private_key", "certificate", "issuer_certificate", "csr":
			default:
				return errors.New("unknown/noncanonical issue protocol field")
			}
			seen[key] = true
		}
		if err := checkIssueValue(d, depth+1); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil {
		return errors.New("incomplete issue protocol container")
	}
	return nil
}

// RunIssueChild is the process-only entrypoint. Its hard-deadline timer exits
// the process even if an SDK call ignores context or the parent has died.
func RunIssueChild(input io.Reader, output io.Writer) int {
	return serveIssueChild(input, output, issueDirect)
}

func serveIssueChild(input io.Reader, output io.Writer, issue func(context.Context, IssueRequest) (*certificate.Resource, error)) int {
	respond := func(res *certificate.Resource, err error) int {
		ok := err == nil && res != nil
		response := issueWireResponse{Version: 1, OK: &ok}
		if ok {
			response.Result = &issueWireResource{Domain: res.Domain, CertURL: res.CertURL, CertStableURL: res.CertStableURL,
				PrivateKey: res.PrivateKey, Certificate: res.Certificate, IssuerCertificate: res.IssuerCertificate, CSR: res.CSR}
		} else {
			response.Error = "ACME attempt returned no certificate"
			if err != nil {
				response.Error = err.Error()
			}
			if len(response.Error) > 32<<10 {
				response.Error = "ACME failure detail exceeds its size limit"
			}
		}
		if json.NewEncoder(output).Encode(response) != nil || !ok {
			return 1
		}
		return 0
	}
	// Reserve one byte beyond the largest valid frame for the owner-loss read;
	// the size limiter itself must not masquerade as a closed control channel.
	reader := bufio.NewReader(io.LimitReader(input, maxIssueRequest+2))
	body, err := reader.ReadBytes('\n')
	var wire issueWireRequest
	if err != nil || len(body) > maxIssueRequest+1 || decodeIssueJSON(body, &wire) != nil || wire.Version != 1 || wire.Deadline.IsZero() || strings.TrimSpace(wire.Request.Email) == "" || len(wire.Request.Domains) == 0 {
		return respond(nil, errors.New("invalid ACME child request"))
	}
	deadline := wire.Deadline
	if maxDeadline := time.Now().Add(IssueProcessTimeout); deadline.After(maxDeadline) {
		deadline = maxDeadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if ctx.Err() != nil {
		return respond(nil, context.DeadlineExceeded)
	}
	// systemd's first TERM targets the whole service cgroup. Let this attempt
	// finish like its parent; a second signal restores the default termination.
	stopping, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() { <-stopping.Done(); stop() }()
	timer := time.AfterFunc(time.Until(deadline), func() { os.Exit(issueTimeoutExit) })
	defer timer.Stop()
	go func() {
		// The parent sends exactly one newline-delimited request, then keeps
		// stdin open. EOF/read failure or any extra input loses that owner.
		_, _ = reader.ReadByte()
		os.Exit(issueOwnerLostExit)
	}()
	res, err := issue(ctx, wire.Request)
	return respond(res, err)
}

func issueDirect(ctx context.Context, request IssueRequest) (*certificate.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(request.Mode)) {
	case "", "http-01":
		return IssueHTTP01Webroot(ctx, request.Email, request.Domains, request.WebrootPath, request.Staging, request.AccountKeyPath)
	case "dns-01":
		return IssueDNS01(ctx, request.Email, request.Domains, request.Staging, request.AccountKeyPath, request.DNSProvider, request.DNSCredentialsEnvFile, request.DNSResolvers)
	default:
		return nil, errors.New("unsupported ACME challenge mode")
	}
}
