package acme

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

// WriteCertificateResource writes Lego output to PEM files and returns paths + validity window.
func WriteCertificateResource(stateDir, certID string, res *certificate.Resource) (fullchainPath, keyPath string, notBefore, notAfter time.Time, err error) {
	if res == nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("nil resource")
	}
	dir := filepath.Join(stateDir, "certs", certID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	fullchainPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(fullchainPath, res.Certificate, 0o640); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if err := os.WriteFile(keyPath, res.PrivateKey, 0o600); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	nb, na, err := parseFirstCertTimes(res.Certificate)
	if err != nil {
		return fullchainPath, keyPath, time.Time{}, time.Time{}, err
	}
	return fullchainPath, keyPath, nb, na, nil
}

func parseFirstCertTimes(pemChain []byte) (time.Time, time.Time, error) {
	var block *pem.Block
	rest := pemChain
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return cert.NotBefore, cert.NotAfter, nil
	}
	return time.Time{}, time.Time{}, fmt.Errorf("no certificate in PEM")
}
