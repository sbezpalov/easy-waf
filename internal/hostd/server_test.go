// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketRoundTrip_nftList(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "hostd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Serve(ctx, sock)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"nft-list"}}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" && resp.Stderr == "" && !resp.OK && resp.Code != 0 {
		t.Fatalf("unexpected empty failure: %+v", resp)
	}
}
