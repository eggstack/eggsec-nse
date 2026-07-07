local http = require "http"
local stdnse = require "stdnse"
description = [[HTTP HEAD against local fixture server.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local response = http.head(host.ip, port.number, "/")
  if response and response.status then
    return "HEAD status=" .. tostring(response.status)
  end
  return "HEAD failed"
end
