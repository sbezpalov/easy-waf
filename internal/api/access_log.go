// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type managementLogFormatter struct {
	middleware.DefaultLogFormatter
}

func (f *managementLogFormatter) NewLogEntry(r *http.Request) middleware.LogEntry {
	// The handler still needs the original query for OAuth and other workflows.
	// Give chi's access logger only the metadata it needs for its journal entry.
	meta := &http.Request{
		Method: r.Method, Host: r.Host, Proto: r.Proto, TLS: r.TLS,
		RemoteAddr: r.RemoteAddr, RequestURI: r.URL.EscapedPath(),
	}
	return f.DefaultLogFormatter.NewLogEntry(meta.WithContext(r.Context()))
}
