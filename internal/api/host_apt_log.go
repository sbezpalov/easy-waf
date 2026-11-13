// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

var (
	downloadAPTLogFn    = runner.DownloadAPTLog
	aptLogDownloadSlots = make(chan struct{}, 2)
)

func (s *Server) hostAptUpgradeLog(w http.ResponseWriter, r *http.Request) {
	select {
	case aptLogDownloadSlots <- struct{}{}:
		defer func() { <-aptLogDownloadSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeClientError(w, http.StatusServiceUnavailable, "saved log downloads busy; retry shortly", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), hostspec.APTLogDownloadTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	rc := http.NewResponseController(w)
	overall, _ := ctx.Deadline()
	if err := rc.SetWriteDeadline(overall); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeInternalError(w, err)
		return
	}
	f, err := os.CreateTemp("", "easy-waf-apt-log-*")
	if err != nil {
		writeInternalError(w, err)
		return
	}
	// Unix removes the name immediately. Platforms that disallow deleting an
	// open file remove it after Close instead; CreateTemp uses private0600 mode.
	unlinked := os.Remove(f.Name()) == nil
	defer func() {
		closeErr := f.Close()
		var removeErr error
		if !unlinked {
			removeErr = os.Remove(f.Name())
		}
		if err := errors.Join(closeErr, removeErr); err != nil {
			log.Printf("api: saved APT log temporary-file cleanup: %v", err)
		}
	}()
	// Do not publish a successful plain-text response before validating the
	// worker's terminal result. Storage is bounded even for a faulty test sink.
	sink := &aptLogSpool{w: f}
	if err := downloadAPTLogFn(r.Context(), sink); err != nil {
		writeInternalError(w, err)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := deliverAptLog(w, r, f, sink.bytes); err != nil {
		// Headers may already be committed. Content-Length lets the client detect
		// a truncated body; never append an error message to the downloaded log.
		log.Printf("api: saved APT log delivery: %v", err)
	}
}

type aptLogSpool struct {
	w     io.Writer
	bytes int64
}

func (s *aptLogSpool) Write(p []byte) (int, error) {
	if int64(len(p)) > hostspec.MaxAPTLogTextBytes-s.bytes {
		return 0, errors.New("saved APT log exceeds download limit")
	}
	n, err := s.w.Write(p)
	s.bytes += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func deliverAptLog(w http.ResponseWriter, r *http.Request, f io.Reader, size int64) error {
	rc := http.NewResponseController(w)
	overall, _ := r.Context().Deadline()
	flushTarget := w
	// chi's non-buffering logger wrapper hides FlushError; unwrap it only for
	// error-aware flushing while writes still go through the logger.
	for {
		wrapped, ok := flushTarget.(middleware.WrapResponseWriter)
		if !ok {
			break
		}
		flushTarget = wrapped.Unwrap()
	}
	flush := http.NewResponseController(flushTarget)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Encoding", "identity")
	w.Header().Set("X-Accel-Buffering", "no")
	buf := make([]byte, hostspec.APTLogChunkBytes)
	var delivered int64
	started := false
	for {
		if err := r.Context().Err(); err != nil {
			return err
		}
		n, readErr := f.Read(buf)
		if n == 0 && errors.Is(readErr, io.EOF) {
			if delivered != size {
				return io.ErrUnexpectedEOF
			}
			if !started {
				w.WriteHeader(http.StatusOK)
			}
			return nil
		}
		if n > 0 {
			if int64(n) > size-delivered {
				return errors.New("saved APT log size changed during delivery")
			}
			deadline := time.Now().Add(aptHTTPWriteTimeout)
			if !overall.IsZero() && overall.Before(deadline) {
				deadline = overall
			}
			if err := rc.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return err
			}
			if !started {
				w.WriteHeader(http.StatusOK)
				started = true
			}
			written, err := w.Write(buf[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
			delivered += int64(written)
			if err := flush.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return err
			}
			if err := rc.SetWriteDeadline(overall); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if delivered == size {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return readErr
		}
	}
}
