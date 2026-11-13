// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

type boundedLogWriter struct{ largest int }

func (w *boundedLogWriter) Write(p []byte) (int, error) {
	w.largest = max(w.largest, len(p))
	if len(p) > 256<<10 {
		return 0, errors.New("whole-log write instead of bounded chunks")
	}
	return len(p), nil
}

func TestAptLogResponsePreservesJSONTextAcrossChunkBoundaries(t *testing.T) {
	var arbitrary []byte
	for i := 0; i < 256; i++ {
		arbitrary = append(arbitrary, byte(i))
	}
	for _, text := range []string{"", "quotes: \"\\\t\n\r\x00 <>&\u2028\u2029", string(arbitrary)} {
		for _, runeText := range []string{"é", "世", "🙂", "\xff\x80\xf0\x9f"} {
			for split := 1; split <= 3; split++ {
				input := strings.Repeat("x", aptLogResponseChunkBytes-split) + runeText + text + "\nlast"
				var output bytes.Buffer
				if err := writeAptLogJSON(&output, iotest.OneByteReader(strings.NewReader(input)), int64(len(input))); err != nil {
					t.Fatal(err)
				}
				var got, want Response
				expected, err := json.Marshal(okResp([]byte(input), nil, 0))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(expected, &want); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(output.Bytes(), &got); err != nil || got != want {
					t.Fatalf("JSON log changed at %q split %d: decode=%v success=%v bytes=%d want=%d", runeText, split, err, got.OK, len(got.Stdout), len(want.Stdout))
				}
			}
		}
	}
}

type failingAptLogReader struct{}

func (failingAptLogReader) Read([]byte) (int, error) {
	return 0, errors.New("fixture log read failure")
}

type failingAptLogWriter struct{ writes int }

func (w *failingAptLogWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, io.ErrClosedPipe
}

func TestAptLogResponseReportsReadFailureAndStopsAfterWriteFailure(t *testing.T) {
	for _, r := range []io.Reader{strings.NewReader("partial"), io.MultiReader(strings.NewReader("partial"), failingAptLogReader{})} {
		var output bytes.Buffer
		if err := writeAptLogJSON(&output, r, 100); err != nil {
			t.Fatal(err)
		}
		var result Response
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.OK || result.Code == 0 || result.Error == "" || result.Stdout != "partial" {
			t.Fatalf("partial read reported success or malformed JSON: %+v %v", result, err)
		}
	}
	writer := &failingAptLogWriter{}
	if err := writeAptLogJSON(writer, strings.NewReader(strings.Repeat("x", 3*aptLogResponseChunkBytes)), 3*aptLogResponseChunkBytes); !errors.Is(err, io.ErrClosedPipe) || writer.writes != 1 {
		t.Fatalf("failed download retried writes: err=%v writes=%d", err, writer.writes)
	}
}

func TestAptLogResponseMissingFileAndOriginalDescriptorSnapshot(t *testing.T) {
	overrideAptActionLogForTest(t)
	var missing bytes.Buffer
	if err := writeAptActionLogResponse(&missing); err != nil {
		t.Fatal(err)
	}
	var result Response
	if err := json.Unmarshal(missing.Bytes(), &result); err != nil || !result.OK || result.Stdout != "" {
		t.Fatalf("missing log compatibility changed: %+v %v", result, err)
	}
	text := strings.Repeat("original\n", aptLogResponseChunkBytes)
	if err := os.WriteFile(aptActionLogPath(), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &aptLogReplacementWriter{t: t}
	if err := writeAptActionLogResponse(writer); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(writer.Bytes(), &result); err != nil || !result.OK || result.Stdout != text {
		t.Fatalf("log replacement changed download snapshot: bytes=%d want=%d err=%v", len(result.Stdout), len(text), err)
	}
}

func TestAptLogResponseUsesBoundedWirePathForBothAliases(t *testing.T) {
	overrideAptActionLogForTest(t)
	text := strings.Repeat("saved line: <>&世🙂\n", 4096)
	if err := os.WriteFile(aptActionLogPath(), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"apt-upgrade-log", "apt-action-log"} {
		t.Run(op, func(t *testing.T) {
			runner := &mockRunner{}
			client, done := aptSocketPair(t, func(conn net.Conn) {
				handleConnRole(t.Context(), conn, &Dispatcher{Runner: runner}, aptWorkerSocket)
			})
			if err := json.NewEncoder(client).Encode(Request{Argv: []string{op}}); err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := json.NewDecoder(client).Decode(&response); err != nil || !response.OK || response.Stdout != text {
				t.Fatalf("saved log wire response changed: size=%d error=%v", len(response.Stdout), err)
			}
			<-done
			if runner.lastName != "" {
				t.Fatal("saved-log download executed a command")
			}
		})
	}
}

type aptLogReplacementWriter struct {
	bytes.Buffer
	t        *testing.T
	replaced bool
}

func (w *aptLogReplacementWriter) Write(p []byte) (int, error) {
	if !w.replaced {
		w.replaced = true
		f, err := os.OpenFile(aptActionLogPath(), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			w.t.Fatal(err)
		}
		_, err = f.WriteString("appended after response began\n")
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			w.t.Fatalf("append fixture: %v %v", err, closeErr)
		}
		if err := writeFileAtomic(aptActionLogPath(), []byte("new operation\n"), 0o600); err != nil {
			w.t.Fatal(err)
		}
	}
	return w.Buffer.Write(p)
}

func TestAptLogResponseDoesNotBufferTheWholeLog(t *testing.T) {
	overrideAptActionLogForTest(t)
	const size = 8 << 20
	if err := os.WriteFile(aptActionLogPath(), []byte(strings.Repeat("x", size)), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &boundedLogWriter{}
	if err := writeAptActionLogResponse(writer); err != nil {
		t.Errorf("unbounded response write: %v (largest=%d)", err, writer.largest)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := writeAptActionLogResponse(io.Discard); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	// Whole-file ReadAll, byte-to-string and whole JSON encoding allocated over
	// 32 MiB for this 8 MiB fixture. Chunk encoding may allocate cumulatively,
	// but must not retain those whole-log copies in the package owner.
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("saved-log response allocated %d bytes for %d-byte log; largest write %d", allocated, size, writer.largest)
	if allocated > 3*size {
		t.Fatalf("saved-log response allocated %d bytes for %d-byte log", allocated, size)
	}
}
