local http = require "http"
local stdnse = require "stdnse"
description = [[HTTP POST against local fixture server.
Sends a POST request and checks the response status.]]
categories = {"intrusive", "vuln"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local post_data = "action=test&target=" .. host.ip
  local response = http.post(
    host.ip,
    port.number,
    "/api/test",
    post_data,
    {content_type = "application/x-www-form-urlencoded"}
  )
  if response and response.status then
    return "POST status=" .. tostring(response.status) .. " body=" .. tostring(response.body)
  end
  return "POST failed"
end
