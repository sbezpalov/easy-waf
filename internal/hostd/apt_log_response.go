// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"unicode/utf8"
)

const aptLogResponseChunkBytes = 32 << 10

func writeAptActionLogResponse(w io.Writer) error {
	f, err := openAptActionLog(aptActionLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return writeResponse(w, okResp(nil, nil, 0))
		}
		return writeResponse(w, failResp(err.Error(), 1))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return writeResponse(w, failResp(err.Error(), 1))
	}
	if !st.Mode().IsRegular() {
		return writeResponse(w, failResp("apt action log is not a regular file", 1))
	}
	// Pin the original descriptor and observed size. Appending/replacing the
	// current log cannot turn one download into an unbounded or mixed response.
	size := min(st.Size(), maxAptActionLogBytes)
	return writeAptLogJSON(w, io.NewSectionReader(f, 0, size), size)
}

// Preserve the existing single JSON response/string stdout without allocating
// the whole log, its string copy and its escaped JSON in the APT owner. UTF-8
// tails stay with the next chunk so encoding/json replaces only invalid input.
func writeAptLogJSON(w io.Writer, r io.Reader, size int64) error {
	bw := bufio.NewWriterSize(w, aptLogResponseChunkBytes)
	if _, err := bw.WriteString(`{"stdout":"`); err != nil {
		return err
	}
	buf := make([]byte, aptLogResponseChunkBytes+utf8.UTFMax)
	var carry int
	var readErr error
	for size > 0 {
		want := int(min(size, aptLogResponseChunkBytes))
		var n int
		n, readErr = io.ReadFull(r, buf[carry:carry+want])
		size -= int64(n)
		data := buf[:carry+n]
		end := len(data)
		if readErr == nil && size > 0 {
			for start := max(0, len(data)-(utf8.UTFMax-1)); start < len(data); start++ {
				if utf8.RuneStart(data[start]) && !utf8.FullRune(data[start:]) {
					end = start
					break
				}
			}
		}
		encoded, err := json.Marshal(string(data[:end]))
		if err != nil {
			return err
		}
		if _, err := bw.Write(encoded[1 : len(encoded)-1]); err != nil {
			return err
		}
		carry = copy(buf, data[end:])
		if readErr != nil {
			break
		}
	}
	// Metadata follows stdout: an I/O failure after a partial read must not be
	// reported as a successful download. A failed socket write returns at once.
	result := struct {
		OK     bool   `json:"ok"`
		Stderr string `json:"stderr"`
		Code   int    `json:"code"`
		Error  string `json:"error,omitempty"`
	}{OK: readErr == nil}
	if readErr != nil {
		result.Code = 1
		result.Error = "cannot read apt action log: " + readErr.Error()
	}
	metadata, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := bw.WriteString(`",`); err != nil {
		return err
	}
	if _, err := bw.Write(metadata[1:]); err != nil {
		return err
	}
	if err := bw.WriteByte('\n'); err != nil {
		return err
	}
	return bw.Flush()
}
