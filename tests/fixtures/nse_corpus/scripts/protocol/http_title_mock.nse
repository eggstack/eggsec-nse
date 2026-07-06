local http = require "http"
local stdnse = require "stdnse"
description = [[HTTP title fetch with local mock service.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local response = http.get("http://127.0.0.1:" .. port.number .. "/")
  if response and response.body then
    local title = string.match(response.body, "<title>(.-)</title>")
    return title or "no title found"
  end
  return "http request failed"
end
