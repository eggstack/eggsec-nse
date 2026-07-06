local http = require "http"
local stdnse = require "stdnse"

description = [[Upstream-style HTTP GET request pattern.
Mimics common http.get() usage found in many web-related NSE scripts.
Uses standard response handling with body/title extraction.]]

categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.service == "http"
end

action = function(host, port)
  local response = http.get("http://" .. host.hostname .. ":" .. port.number .. "/", {timeout = 5000})
  if response and response.body then
    local title = string.match(response.body, "<title>(.-)</title>")
    if title then
      return "HTTP Title: " .. title
    end
    return "HTTP response received (no title)"
  end
  return "HTTP request failed"
end
