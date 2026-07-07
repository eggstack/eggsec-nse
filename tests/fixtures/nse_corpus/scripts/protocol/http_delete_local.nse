local http = require "http"
local stdnse = require "stdnse"
description = [[HTTP DELETE against local fixture server.]]
categories = {"intrusive", "vuln"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local response = http.delete(
    host.ip,
    port.number,
    "/api/test",
    {content_type = "application/x-www-form-urlencoded"}
  )
  if response and response.status then
    return "DELETE status=" .. tostring(response.status) .. " body=" .. tostring(response.body)
  end
  return "DELETE failed"
end
