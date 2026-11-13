// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
)

func accountKeyID(key crypto.PrivateKey) (string, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("unexpected key type %T", key)
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(public)), nil
}

func TestAccountKeyConcurrentCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme", "account.pem")
	const writers = 12
	start := make(chan struct{})
	ids := make(chan string, writers)
	errs := make(chan error, writers)
	stopReader := make(chan struct{})
	readerResult := make(chan error, 1)
	go func() {
		var first string
		for {
			select {
			case <-stopReader:
				readerResult <- nil
				return
			default:
			}
			data, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				time.Sleep(time.Millisecond)
				continue
			}
			if err != nil {
				readerResult <- err
				return
			}
			key, err := certcrypto.ParsePEMPrivateKey(data)
			if err != nil {
				readerResult <- fmt.Errorf("reader observed incomplete account key")
				return
			}
			id, err := accountKeyID(key)
			if err != nil {
				readerResult <- err
				return
			}
			if first != "" && first != id {
				readerResult <- fmt.Errorf("reader observed account key replacement")
				return
			}
			first = id
		}
	}()
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			<-start
			key, err := loadOrCreatePrivateKey(path)
			if err != nil {
				errs <- err
				return
			}
			id, err := accountKeyID(key)
			if err != nil {
				errs <- err
				return
			}
			ids <- id
		})
	}
	close(start)
	wg.Wait()
	close(stopReader)
	if err := <-readerResult; err != nil {
		t.Error(err)
	}
	close(ids)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := certcrypto.ParsePEMPrivateKey(data)
	if err != nil {
		t.Fatal("canonical account key is invalid")
	}
	want, err := accountKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	for id := range ids {
		if id != want {
			t.Error("creator returned an account identity different from the persisted key")
		}
	}
	assertNoAccountKeyStages(t, path)
}

func assertNoAccountKeyStages(t *testing.T, path string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary key files remain: count=%d, error=%v", len(files), err)
	}
}

func TestAccountKeyExistingFiles(t *testing.T) {
	for _, kind := range []certcrypto.KeyType{certcrypto.RSA2048, certcrypto.EC256} {
		t.Run(string(kind), func(t *testing.T) {
			key, err := certcrypto.GeneratePrivateKey(kind)
			if err != nil {
				t.Fatal(err)
			}
			original := certcrypto.PEMEncode(key)
			pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
			for _, encoded := range [][]byte{original, pkcs8PEM} {
				testExistingAccountKey(t, key, encoded)
			}
		})
	}
	for _, data := range [][]byte{nil, []byte("-----BEGIN RSA PRIVATE KEY-----\ninterrupted")} {
		path := filepath.Join(t.TempDir(), "account.pem")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreatePrivateKey(path); err == nil {
			t.Fatal("corrupt existing key must fail without rotation")
		}
		if err := writeAccountKeyExclusive(path, []byte("losing candidate")); !os.IsExist(err) {
			t.Fatalf("corrupt destination was not preserved: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("corrupt existing key was overwritten")
		}
		assertNoAccountKeyStages(t, path)
	}
}

func testExistingAccountKey(t *testing.T, key crypto.PrivateKey, original []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "account.pem")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := accountKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := accountKeyID(loaded)
	if err != nil || got != want {
		t.Fatal("existing account identity changed")
	}
	// Exercise a publisher that observed absence before another process
	// won. Even a different candidate must not replace existing bytes.
	if err := writeAccountKeyExclusive(path, []byte("losing candidate")); !os.IsExist(err) {
		t.Fatalf("expected destination-exists error, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("existing account file changed")
	}
	assertNoAccountKeyStages(t, path)
}

func TestAccountKeyPublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme", "account.pem")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// An interrupted writer's private partial stage is never the account key.
	orphan := filepath.Join(filepath.Dir(path), ".account.pem.tmp-interrupted")
	if err := os.WriteFile(orphan, []byte("partial PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accountKeyID(key); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for target, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
			info, err := os.Stat(target)
			if err != nil || info.Mode().Perm() != want {
				t.Fatalf("private key permissions: %v", err)
			}
		}
	}
	got, err := os.ReadFile(orphan)
	if err != nil || string(got) != "partial PEM" {
		t.Fatal("unowned interrupted stage was changed")
	}
	if err := os.Remove(orphan); err != nil {
		t.Fatal(err)
	}
	assertNoAccountKeyStages(t, path)

	// A non-file destination and an invalid parent cannot trigger a fallback.
	if err := writeAccountKeyExclusive(filepath.Dir(path), []byte("candidate")); err == nil {
		t.Fatal("publication over directory succeeded")
	}
	if _, err := loadOrCreatePrivateKey(filepath.Join(path, "account.pem")); err == nil {
		t.Fatal("publication under a regular file succeeded")
	}
	assertNoAccountKeyStages(t, filepath.Dir(path))
	assertNoAccountKeyStages(t, path)
}

func TestAccountKeyProcessHelper(_ *testing.T) {
	if os.Getenv("EASY_WAF_ACCOUNT_KEY_TEST") != "1" {
		return
	}
	_, _ = io.WriteString(os.Stdout, "ready\n")
	if _, err := io.CopyN(io.Discard, os.Stdin, 1); err != nil {
		os.Exit(2)
	}
	key, err := loadOrCreatePrivateKey("account.pem")
	if err != nil {
		os.Exit(3)
	}
	id, err := accountKeyID(key)
	if err != nil {
		os.Exit(4)
	}
	_, _ = io.WriteString(os.Stdout, id)
	os.Exit(0)
}

func TestAccountKeyIndependentProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.pem")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type child struct {
		cmd    *exec.Cmd
		input  io.WriteCloser
		output *bufio.Reader
	}
	children := make([]child, 0, 6)
	defer func() {
		cancel()
		for _, c := range children {
			_ = c.input.Close()
			if c.cmd.ProcessState == nil {
				_ = c.cmd.Wait()
			}
		}
	}()
	for range 6 {
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestAccountKeyProcessHelper$")
		cmd.Dir = filepath.Dir(path)
		cmd.Env = append(os.Environ(), "EASY_WAF_ACCOUNT_KEY_TEST=1")
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			_ = input.Close()
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			_ = input.Close()
			_ = output.Close()
			t.Fatal(err)
		}
		c := child{cmd: cmd, input: input, output: bufio.NewReader(output)}
		children = append(children, c)
		if ready, err := c.output.ReadString('\n'); err != nil || ready != "ready\n" {
			t.Fatal("account key child did not become ready")
		}
	}
	for _, c := range children {
		if _, err := io.WriteString(c.input, "\n"); err != nil {
			t.Fatal(err)
		}
		_ = c.input.Close()
	}
	var want string
	for _, c := range children {
		id, err := io.ReadAll(c.output)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.cmd.Wait(); err != nil {
			t.Fatalf("account key child failed: %v", err)
		}
		if want == "" {
			want = string(id)
		}
		if len(id) != 64 || strings.TrimSpace(string(id)) != want {
			t.Fatal("independent issuers disagree on account identity")
		}
	}
	key, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := accountKeyID(key)
	if err != nil || id != want {
		t.Fatal("process account identity differs from persisted key")
	}
	assertNoAccountKeyStages(t, path)
}
