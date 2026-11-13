// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

func TestAptSavedLogDownloadPreservesSnapshotAndDoesNotLaunchWork(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	t.Cleanup(resetAptUpgradeState)
	text := strings.Repeat("x", aptLogResponseChunkBytes-1) + "🙂\xff\x80\n" + strings.Repeat("<>&世\n", 10000)
	if err := os.WriteFile(aptActionLogPath(), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &aptLogReplacementWriter{t: t}
	dispatchAptLogDownload(writer)
	events := readAptDownloadEvents(t, bytes.NewReader(writer.Bytes()))
	var got strings.Builder
	for _, event := range events[:len(events)-1] {
		if event.Type != "line" || len(event.Data) > 3*(aptLogResponseChunkBytes+3) {
			t.Fatalf("unexpected saved-log chunk: type=%s bytes=%d", event.Type, len(event.Data))
		}
		got.WriteString(event.Data)
	}
	expectedJSON, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	var expected string
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if got.String() != expected || last.Type != "exit" || last.Code != 0 || last.Error != "" || aptActionCurrent != nil {
		t.Fatal("snapshot changed, lost completion, or launched/replaced an APT action")
	}
}

func TestAptSavedLogDownloadHandlesMissingUnsafeAndFailedWriter(t *testing.T) {
	overrideAptActionLogForTest(t)
	var missing bytes.Buffer
	dispatchAptLogDownload(&missing)
	events := readAptDownloadEvents(t, &missing)
	if len(events) != 1 || events[0].Type != "exit" || events[0].Code != 0 {
		t.Fatal("missing saved log should be an empty completed snapshot")
	}
	if err := os.Mkdir(aptActionLogPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	var invalid bytes.Buffer
	dispatchAptLogDownload(&invalid)
	events = readAptDownloadEvents(t, &invalid)
	if len(events) != 1 || events[0].Type != "exit" || events[0].Code == 0 || events[0].Error == "" {
		t.Fatal("non-regular saved log reported success")
	}
	if err := os.Remove(aptActionLogPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aptActionLogPath(), []byte(strings.Repeat("x", 3*aptLogResponseChunkBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &failingAptLogWriter{}
	dispatchAptLogDownload(writer)
	if writer.writes != 1 {
		t.Fatalf("failed read-only observer received another attempted write: %d", writer.writes)
	}
}

func readAptDownloadEvents(t *testing.T, r io.Reader) []streamEvent {
	t.Helper()
	decoder := json.NewDecoder(r)
	var events []streamEvent
	for {
		var event streamEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("saved-log response has no terminal event")
	}
	return events
}

type truncatingAptLogWriter struct {
	bytes.Buffer
	t         *testing.T
	truncated bool
}

func (w *truncatingAptLogWriter) Write(p []byte) (int, error) {
	if !w.truncated {
		w.truncated = true
		if err := os.Truncate(aptActionLogPath(), 0); err != nil {
			w.t.Fatal(err)
		}
	}
	return w.Buffer.Write(p)
}

func TestAptSavedLogDownloadReportsTruncationAndBoundsEscapedFrames(t *testing.T) {
	overrideAptActionLogForTest(t)
	if err := os.WriteFile(aptActionLogPath(), []byte(strings.Repeat("x", 3*aptLogResponseChunkBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &truncatingAptLogWriter{t: t}
	dispatchAptLogDownload(writer)
	events := readAptDownloadEvents(t, bytes.NewReader(writer.Bytes()))
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code == 0 || last.Error == "" {
		t.Fatal("truncated snapshot reported success")
	}
	if err := os.WriteFile(aptActionLogPath(), []byte(strings.Repeat("\x00", 2*aptLogResponseChunkBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	bounded := &boundedLogWriter{}
	dispatchAptLogDownload(io.MultiWriter(&output, bounded))
	events = readAptDownloadEvents(t, &output)
	if len(events) != 3 || events[2].Code != 0 || len(events[0].Data) != aptLogResponseChunkBytes || bounded.largest > 256<<10 {
		t.Fatal("escaped source chunk exceeded the bounded protocol frame")
	}
}

func TestAptSavedLogDownloadWireOpcodeIsReadOnlyAndTakesNoPath(t *testing.T) {
	overrideAptActionLogForTest(t)
	if err := os.WriteFile(aptActionLogPath(), []byte("saved\ntext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isAPTWorkerOpcode("apt-action-log-stream") || !isAPTStreamOpcode("apt-action-log-stream") || isAPTMutationOpcode("apt-action-log-stream") {
		t.Fatal("saved-log opcode escaped its read-only worker classification")
	}
	for _, args := range [][]string{{"apt-action-log-stream"}, {"apt-action-log-stream", "/etc/shadow"}} {
		runner := &mockRunner{}
		client, done := aptSocketPair(t, func(conn net.Conn) {
			handleConnRole(t.Context(), conn, &Dispatcher{Runner: runner}, aptWorkerSocket)
		})
		if err := json.NewEncoder(client).Encode(Request{Argv: args}); err != nil {
			t.Fatal(err)
		}
		events := readSocketStreamEvents(t, client)
		<-done
		last := events[len(events)-1]
		if runner.lastName != "" || (len(args) == 1 && (last.Code != 0 || len(events) != 2 || events[0].Data != "saved\ntext\n")) || (len(args) > 1 && (last.Code == 0 || len(events) != 1)) {
			t.Fatal("saved-log wire protocol changed or accepted an arbitrary path")
		}
	}
}
