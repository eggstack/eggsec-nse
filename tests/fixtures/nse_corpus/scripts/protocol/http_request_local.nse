local http = require "http"
local stdnse = require "stdnse"
description = [[Generic HTTP request against local fixture server.]]
categories = {"intrusive", "vuln"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local response = http.request("GET", host.ip, port.number, "/")
  if response and response.status then
    return "REQUEST status=" .. tostring(response.status) .. " body=" .. tostring(response.body)
  end
  return "REQUEST failed"
end
