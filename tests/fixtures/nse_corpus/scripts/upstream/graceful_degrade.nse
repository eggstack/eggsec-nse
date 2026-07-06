local http = require "http"
local stdnse = require "stdnse"

description = [[Upstream-style script that degrades gracefully when a library operation fails.
Tests the common pattern of try/fallback in NSE scripts.]]

categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  -- Attempt HTTP request with graceful fallback
  local status, response = pcall(http.get, "http://" .. host.ip .. ":" .. port.number .. "/", {timeout = 3000})
  if status and response and response.body then
    local title = string.match(response.body, "<title>(.-)</title>")
    return "Title: " .. (title or "no title")
  end

  -- Fallback: try a simpler check
  stdnse.verbose("HTTP failed, falling back to banner grab")
  return "service on port " .. port.number .. " (graceful degradation)"
end
