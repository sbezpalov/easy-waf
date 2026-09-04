// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package apt

import (
	"context"
	"errors"
	"testing"
)

func TestParseAutoremovePackages(t *testing.T) {
	out := `Reading package lists...
Remv linux-image-extra-6.8.0-45 [6.8.0-45.45]
Remv linux-modules-extra-6.8.0-45 [6.8.0-45.45]
0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.
`
	pkgs := ParseAutoremovePackages(out)
	if len(pkgs) != 2 {
		t.Fatalf("packages: %v", pkgs)
	}
	if pkgs[0] != "linux-image-extra-6.8.0-45" || pkgs[1] != "linux-modules-extra-6.8.0-45" {
		t.Fatalf("unexpected: %v", pkgs)
	}
}

func TestAutoremoveNothingToDo(t *testing.T) {
	st := UpdatesStatus{Output: "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."}
	if !AutoremoveNothingToDo(st) {
		t.Fatal("expected nothing to do")
	}
	st = UpdatesStatus{
		Output:   "Remv foo",
		Packages: []string{"foo"},
	}
	if AutoremoveNothingToDo(st) {
		t.Fatal("expected work to do")
	}
}

func TestAutoremovePreview(t *testing.T) {
	orig := aptPrivilegedFn
	defer func() { aptPrivilegedFn = orig }()
	aptPrivilegedFn = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) != 1 || args[0] != "apt-autoremove-simulate" {
			t.Fatalf("args: %v", args)
		}
		return []byte("Remv orphan-pkg [1.0]\n0 upgraded, 0 newly installed, 1 to remove\n"), nil
	}
	st, err := AutoremovePreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Packages) != 1 || st.Packages[0] != "orphan-pkg" {
		t.Fatalf("packages: %v", st.Packages)
	}
}

func TestParseCacheSizeBytes(t *testing.T) {
	n, err := ParseCacheSizeBytes("340123456\t/var/cache/apt/archives\n")
	if err != nil || n != 340123456 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	n, err = ParseCacheSizeBytes("")
	if err != nil || n != 0 {
		t.Fatalf("empty: n=%d err=%v", n, err)
	}
}

func TestCacheSizeBytes(t *testing.T) {
	orig := aptPrivilegedFn
	defer func() { aptPrivilegedFn = orig }()
	aptPrivilegedFn = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] != "apt-cache-size" {
			t.Fatalf("args: %v", args)
		}
		return []byte("1024\t/var/cache/apt/archives\n"), nil
	}
	n, err := CacheSizeBytes(context.Background())
	if err != nil || n != 1024 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestCleanCache(t *testing.T) {
	orig := aptPrivilegedFn
	defer func() { aptPrivilegedFn = orig }()
	var called bool
	aptPrivilegedFn = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "apt-clean" {
			called = true
			return nil, nil
		}
		return nil, errors.New("unexpected")
	}
	if err := CleanCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("apt-clean not called")
	}
}

func TestAutoremovePreview_error(t *testing.T) {
	orig := aptPrivilegedFn
	defer func() { aptPrivilegedFn = orig }()
	aptPrivilegedFn = func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("broker down")
	}
	_, err := AutoremovePreview(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
