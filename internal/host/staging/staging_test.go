// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package staging

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestWithFileRemovesInputAfterSuccessAndFailure(t *testing.T) {
	operationErr := errors.New("broker failed")
	for _, tc := range []struct {
		name string
		err  error
	}{{"success", nil}, {"failure", operationErr}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var staged string
			err := withFile(dir, "netplan-*.yaml", []byte("private fixture"), func(path string) error {
				staged = path
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "private fixture" {
					t.Fatalf("staged content: %q, %v", data, err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
					t.Fatalf("secret mode = %v", info.Mode())
				}
				return tc.err
			})
			if !errors.Is(err, tc.err) {
				t.Fatalf("operation result lost: %v", err)
			}
			if staged == "" {
				t.Fatal("consumer was not called")
			}
			if _, err := os.Stat(staged); !os.IsNotExist(err) {
				t.Fatalf("staged input retained: %v", err)
			}
		})
	}
}

func TestWithFileCreationFailureDoesNotCallConsumer(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := withFile(filepath.Join(blocker, "staging"), "input-*", nil, func(string) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("creation error did not stop dispatch: called=%v err=%v", called, err)
	}
}

func TestWithFileConcurrentRequestsHaveIndependentInputs(t *testing.T) {
	dir := t.TempDir()
	entered := make(chan string, 2)
	results := make(chan error, 2)
	release := make(chan struct{})
	defer close(release)
	for _, content := range []string{"first request", "second request"} {
		go func(content string) {
			results <- withFile(dir, "netplan-*.yaml", []byte(content), func(path string) error {
				entered <- path
				<-release
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if string(data) != content {
					return errors.New("concurrent input was overwritten")
				}
				return nil
			})
		}(content)
	}
	paths := make([]string, 0, 2)
	for len(paths) < 2 {
		select {
		case path := <-entered:
			paths = append(paths, path)
		case err := <-results:
			t.Fatalf("consumer was not reached: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("consumers did not start")
		}
	}
	if paths[0] == paths[1] {
		t.Fatal("concurrent requests shared a staged path")
	}
	// Let each request read its input and complete cleanup before checking results.
	release <- struct{}{}
	release <- struct{}{}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging files retained: %v, %v", entries, err)
	}
}

func TestWithFileReportsCleanupErrorWithoutHidingBrokerError(t *testing.T) {
	dir := t.TempDir()
	brokerErr := errors.New("broker refused")
	err := withFile(dir, "input-*", nil, func(path string) error {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "keep"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return brokerErr
	})
	if !errors.Is(err, brokerErr) {
		t.Fatalf("broker failure hidden: %v", err)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("cleanup failure hidden: %v", err)
	}
}
