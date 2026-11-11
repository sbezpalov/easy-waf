-- Copyright 2026 Sergey Bezpalov
-- SPDX-License-Identifier: Apache-2.0
--
-- Forward authentication (ADR 0005): asks an auth service such as Authelia
-- before a request reaches an application's servers. It fails closed: no
-- answer, a timeout or any status other than 2xx leaves txn.auth_ok false.
-- Uses only HAProxy's built-in httpclient (2.5+).

local forwarded = { "cookie", "authorization", "proxy-authorization", "user-agent", "accept" }
local identity = { "remote-user", "remote-groups", "remote-email", "remote-name" }

local function first(headers, name)
  local v = headers and headers[name]
  if type(v) ~= "table" then
    return v
  end
  return v[0] or v[1]
end

core.register_action("easywaf_auth", { "http-req" }, function(txn, url)
  txn:set_var("txn.auth_ok", false)
  local hdrs = txn.http:req_get_headers()
  local req = {}
  for _, h in ipairs(forwarded) do
    local v = first(hdrs, h)
    if v then
      req[h] = { v }
    end
  end
  local host = first(hdrs, "host") or ""
  local ssl = txn.f:ssl_fc()
  local proto = (ssl == true or ssl == 1) and "https" or "http"
  local uri = txn.f:pathq() or "/"
  req["x-forwarded-method"] = { txn.f:method() }
  req["x-forwarded-proto"] = { proto }
  req["x-forwarded-host"] = { host }
  req["x-forwarded-uri"] = { uri }
  req["x-forwarded-for"] = { txn.f:src() }
  req["x-original-url"] = { proto .. "://" .. host .. uri }
  local ok, res = pcall(function()
    return core.httpclient():get({ url = url, headers = req, timeout = 3000 })
  end)
  if not ok or type(res) ~= "table" or not res.status then
    return
  end
  if res.status >= 200 and res.status < 300 then
    txn:set_var("txn.auth_ok", true)
    for _, h in ipairs(identity) do
      local v = first(res.headers, h)
      if v then
        txn:set_var("txn.auth_" .. (h:gsub("-", "_")), v)
      end
    end
    return
  end
  local loc = first(res.headers, "location")
  if loc and (res.status == 301 or res.status == 302 or res.status == 303 or res.status == 307) then
    txn:set_var("txn.auth_location", loc)
  end
end, 1)
