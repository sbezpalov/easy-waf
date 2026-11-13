// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// The apt action log lives in the root-only hostd state directory. These
// wrappers keep access descriptor-anchored there and fall back to plain file
// access only for the temp-directory override tests use. See statefile.go.

const maxAptActionLogBytes = hostspec.MaxAPTLogBytes

func underStateDir(path string) bool {
	_, err := stateRel(path)
	return err == nil
}

func createAptActionLog(path string) (*os.File, error) {
	if underStateDir(path) {
		// Replace the inode: old followers must retain their original log.
		if err := stateWriteFile(path, nil, 0o640); err != nil {
			return nil, err
		}
		return stateCreateFile(path, 0o640)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, nil, 0o640); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY, 0)
}

func openAptActionLog(path string) (*os.File, error) {
	if underStateDir(path) {
		return stateOpenFile(path)
	}
	// Root.Open uses delete sharing on Windows too, permitting replacement
	// while a follower still owns its read descriptor for the previous inode.
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(filepath.Base(path))
}

const (
	maxAptReplayBatchBytes = 1 << 20
	maxAptReplayBatchLines = 1024
)

// Use logical complete-line offsets, not the buffered reader's physical file
// position. A partial EOF stays pending until the writer appends its newline.
func readAptActionLogFileFrom(f *os.File, offset int64) (lines []string, newOffset int64, err error) {
	st, err := f.Stat()
	if err != nil {
		return nil, offset, err
	}
	if offset < 0 || offset > st.Size() {
		return nil, offset, errors.New("apt action log was truncated or offset is invalid")
	}
	newOffset = offset
	reader := bufio.NewReader(io.NewSectionReader(f, offset, maxAptReplayBatchBytes+maxAptOutputLineBytes))
	for newOffset-offset < maxAptReplayBatchBytes && len(lines) < maxAptReplayBatchLines {
		line, readErr := reader.ReadString('\n')
		if len(line) > maxAptOutputLineBytes || (len(line) == maxAptOutputLineBytes && errors.Is(readErr, io.EOF)) {
			return lines, newOffset, errors.New("apt action log line exceeds capture limit")
		}
		if errors.Is(readErr, io.EOF) {
			return lines, newOffset, nil
		}
		if readErr != nil {
			return lines, newOffset, readErr
		}
		newOffset += int64(len(line))
		lines = append(lines, strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
	}
	return lines, newOffset, nil
}

type aptLogFile interface {
	io.Writer
	Sync() error
	Close() error
}

// Logging must not stop a package transaction, but incomplete persistence must
// be visible in its final stream/status result. Keep the first I/O error.
type aptLogSink struct {
	file aptLogFile
	err  error
	size int64
}

func (s *aptLogSink) line(line string) {
	if s.file == nil || s.err != nil {
		return
	}
	if int64(len(line))+1 > maxAptActionLogBytes-s.size {
		s.err = errors.New("saved log exceeds 64 MiB limit")
		return
	}
	n, err := fmt.Fprintln(s.file, line)
	if err == nil && n != len(line)+1 {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.err = fmt.Errorf("write: %w", err)
		return
	}
	s.size += int64(len(line)) + 1
	if err := s.file.Sync(); err != nil {
		s.err = fmt.Errorf("sync: %w", err)
	}
}

func (s *aptLogSink) close() error {
	if s.file != nil {
		s.err = errors.Join(s.err, s.file.Close())
	}
	return s.err
}

func readAptActionLog(path string) ([]byte, error) {
	f, err := openAptActionLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxAptActionLogBytes))
}
