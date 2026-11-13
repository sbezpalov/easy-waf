// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"io"
	"os"
	"time"
)

// A saved-log snapshot is independent of retained operation/result state. This
// read-only opcode must never acquire-or-start an APT action or follow later data.
func dispatchAptLogDownload(w io.Writer) {
	sc := newAptStreamConn(w)
	sc.expires = time.Now().Add(hostCommandTimeout)
	fail := func(err error) {
		_ = sc.writeEvent(streamEvent{Type: "exit", Code: -1, Error: "cannot read saved APT log: " + err.Error()})
	}
	f, err := openAptActionLog(aptActionLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			_ = sc.writeEvent(streamEvent{Type: "exit", Code: 0})
		} else {
			fail(err)
		}
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		fail(err)
		return
	}
	if !st.Mode().IsRegular() {
		fail(os.ErrInvalid)
		return
	}
	size := min(st.Size(), maxAptActionLogBytes)
	readErr, deliveryErr := readAptLogChunks(io.NewSectionReader(f, 0, size), size, func(data []byte) error {
		return sc.writeEvent(streamEvent{Type: "line", Data: string(data)})
	})
	if deliveryErr != nil {
		return // A failed observer never gets another attempted write.
	}
	if readErr != nil {
		fail(readErr)
		return
	}
	_ = sc.writeEvent(streamEvent{Type: "exit", Code: 0})
}
