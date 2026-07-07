local http = require "http"
local stdnse = require "stdnse"
description = [[HTTP GET against local fixture server.
Fetches the root page and extracts the title.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local response = http.get(host.ip, port.number, "/")
  if response and response.body then
    local title = string.match(response.body, "<title>(.-)</title>")
    if title then
      return "title: " .. title .. " (status=" .. tostring(response.status) .. ")"
    end
    return "no title (status=" .. tostring(response.status) .. ")"
  end
  return "HTTP GET failed"
end
