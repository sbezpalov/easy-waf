// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"log"
	"net/http"
)

// writeClientError returns a stable JSON {"error": public} to the client and
// logs cause server-side. Internal details (HAProxy -c output, broker/journal
// paths, DB/bcrypt/JWT internals) must not reach the UI toast surface.
func writeClientError(w http.ResponseWriter, status int, public string, cause error) {
	if public == "" {
		if status >= 500 {
			public = "internal error"
		} else {
			public = "request failed"
		}
	}
	if cause != nil {
		log.Printf("api: status=%d client=%q: %v", status, public, cause)
	}
	writeJSON(w, status, map[string]string{"error": public})
}

// writeInternalError is the 500 path: always a generic client message.
func writeInternalError(w http.ResponseWriter, cause error) {
	writeClientError(w, http.StatusInternalServerError, "internal error", cause)
}
