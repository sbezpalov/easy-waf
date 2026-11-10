// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package testcert writes throwaway self-signed HAProxy bundles for tests.
// The files are generated when a test needs them and are not stored in git.
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GoldenBundles are the three crt-list fixtures the HAProxy golden tests open.
func GoldenBundles(dir string) error {
	pairs := []struct {
		name, cn string
	}{
		{"bundle-a.pem", "a.example.com"},
		{"bundle-b.pem", "b.example.org"},
		{"bundle-c.pem", "c.example.net"},
	}
	for _, p := range pairs {
		if err := WriteBundle(filepath.Join(dir, p.name), p.cn); err != nil {
			return err
		}
	}
	return nil
}

// WriteBundle writes a certificate and its private key in the single PEM file
// HAProxy accepts on a crt-list line. The name is a documentation name
// (example.com, example.org, example.net); the key is new every call.
func WriteBundle(path, commonName string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	body = append(body, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	return nil
}

// MustGoldenBundles is for TestMain, where a returned error has nowhere to go.
func MustGoldenBundles(dir string) {
	if err := GoldenBundles(dir); err != nil {
		panic(fmt.Errorf("test certificates: %w", err))
	}
}
