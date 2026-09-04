// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"fmt"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

type appSecCtx struct {
	Root     RenderInput
	App      AppRender
	HostACL  string
	SkipACME bool
}

func appSec(root RenderInput, a AppRender, hostACL string, skipACME bool) appSecCtx {
	return appSecCtx{Root: root, App: a, HostACL: hostACL, SkipACME: skipACME}
}

func acmeSuffix(skip bool) string {
	if skip {
		return " !acme"
	}
	return ""
}

func backendTLSOptions(a AppRender) string {
	app := a.Application
	if !app.BackendHTTPS {
		return ""
	}
	config.NormalizeBackendTLS(&app)
	if app.BackendTLSVerify == config.BackendTLSVerifyNone {
		return " ssl verify none"
	}
	ca := strings.TrimSpace(app.BackendTLSCAFile)
	if ca == "" {
		ca = config.DefaultSystemCABundle
	}
	verifyHost := strings.TrimSpace(app.BackendTLSServerName)
	if verifyHost == "" {
		verifyHost = strings.Trim(app.BackendHost, "[]")
	}
	return fmt.Sprintf(" ssl verify required ca-file %s sni str(%s) verifyhost %s", ca, verifyHost, verifyHost)
}
