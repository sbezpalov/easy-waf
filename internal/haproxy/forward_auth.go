// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import _ "embed" // forward-auth.lua

// DefaultForwardAuthLuaPath is where the package installs forward-auth.lua.
const DefaultForwardAuthLuaPath = "/usr/share/easy-waf/haproxy/forward-auth.lua"

// ForwardAuthLua is the HAProxy Lua action behind forward_auth_url.
//
//go:embed forward-auth.lua
var ForwardAuthLua string
