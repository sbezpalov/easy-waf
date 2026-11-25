// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func composeEdgeStatus(base config.EdgeStatus, revisionSHA string, runtimeErr error, checkedAt time.Time) config.EdgeStatus {
	base.Runtime = config.EdgeRuntimeStatus{
		State:     config.EdgeRuntimeUnknown,
		CheckedAt: checkedAt.UTC(),
	}
	if runtimeErr != nil || revisionSHA == "" {
		base.Runtime.ErrorCode = "live_artifact_unavailable"
		return base
	}
	base.Runtime.State = config.EdgeRuntimeKnown
	base.Runtime.RevisionSHA = revisionSHA
	return base
}

func (s *Server) handleEdgeStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.edgeStatus(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) edgeStatus(ctx context.Context) (config.EdgeStatus, error) {
	status, err := s.Eng.Store.GetEdgeStatus(ctx)
	if err != nil {
		return status, err
	}
	sha, runtimeErr := s.Eng.LiveHAProxySHA256()
	return composeEdgeStatus(status, sha, runtimeErr, time.Now().UTC()), nil
}
