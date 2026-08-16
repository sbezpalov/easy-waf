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

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	return user, client, nil
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

	user, client, err := registerLegoClient(email, accountKeyPath, staging)
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
	res, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}
	_ = ctx
	return res, nil
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
