// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
)

// LegoUser implements acme.User for Lego.
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string {
	return u.Email
}

func (u *LegoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// registerLegoClient builds user + lego.Client (challenge not yet configured).
func registerLegoClient(email, accountKeyPath string, staging bool) (*LegoUser, *lego.Client, error) {
	return registerLegoClientTimeout(email, accountKeyPath, staging, 0)
}

func registerLegoClientTimeout(email, accountKeyPath string, staging bool, timeout time.Duration) (*LegoUser, *lego.Client, error) {
	privateKey, err := loadOrCreatePrivateKey(accountKeyPath)
	if err != nil {
		return nil, nil, err
	}
	user := &LegoUser{Email: email, key: privateKey}

	cfg := lego.NewConfig(user)
	if staging {
		cfg.CADirURL = lego.LEDirectoryStaging
	} else {
		cfg.CADirURL = lego.LEDirectoryProduction
	}
	if timeout > 0 {
		cfg.Certificate.Timeout = timeout
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	return user, client, nil
}

// obtainWithContext runs Lego Obtain and returns when ctx is done. Lego's
// ObtainRequest has no Context field; we bound Certificate.Timeout from the
// deadline and abandon waiting on cancel (the in-flight goroutine may still
// finish and burn CA quota — callers heartbeat the claim and persist orphans).
func obtainWithContext(ctx context.Context, client *lego.Client, request certificate.ObtainRequest) (*certificate.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type outcome struct {
		res *certificate.Resource
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := client.Certificate.Obtain(request)
		ch <- outcome{res, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case out := <-ch:
		return out.res, out.err
	}
}

func registerAccount(client *lego.Client, user *LegoUser) error {
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		reg, err = client.Registration.ResolveAccountByKey()
		if err != nil {
			return err
		}
	}
	user.Registration = reg
	return nil
}

// IssueHTTP01Webroot obtains a certificate using HTTP-01 with a filesystem webroot (HAProxy must expose it on :80).
func IssueHTTP01Webroot(ctx context.Context, email string, domains []string, webrootPath string, staging bool, accountKeyPath string) (*certificate.Resource, error) {
	if email == "" || len(domains) == 0 {
		return nil, fmt.Errorf("email and domains required")
	}
	if webrootPath == "" {
		return nil, fmt.Errorf("webroot required")
	}
	if err := os.MkdirAll(webrootPath, 0o755); err != nil {
		return nil, err
	}

	timeout := time.Duration(0)
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
		if timeout < time.Minute {
			timeout = time.Minute
		}
	}
	user, client, err := registerLegoClientTimeout(email, accountKeyPath, staging, timeout)
	if err != nil {
		return nil, err
	}

	prov, err := webroot.NewHTTPProvider(webrootPath)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetHTTP01Provider(prov); err != nil {
		return nil, err
	}

	if err := registerAccount(client, user); err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	return obtainWithContext(ctx, client, request)
}

// acmeAccountKeyType is the single policy for ACME account keys. The two
// branches below used to generate keys in different ways — certcrypto in one,
// a raw rsa.GenerateKey in the other — so changing the policy meant changing it
// in two places and noticing both.
const acmeAccountKeyType = certcrypto.RSA2048

func generateACMEAccountKey() (*rsa.PrivateKey, error) {
	k, err := certcrypto.GeneratePrivateKey(acmeAccountKeyType)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("acme: unexpected account key type %T", k)
	}
	return rk, nil
}

func loadOrCreatePrivateKey(path string) (crypto.PrivateKey, error) {
	if path == "" {
		return generateACMEAccountKey()
	}
	if b, err := os.ReadFile(path); err == nil {
		return certcrypto.ParsePEMPrivateKey(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := generateACMEAccountKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
