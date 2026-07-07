local http = require "http"
local stdnse = require "stdnse"
description = [[HTTP PUT against local fixture server.]]
categories = {"intrusive", "vuln"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local put_data = "action=update&target=" .. host.ip
  local response = http.put(
    host.ip,
    port.number,
    "/api/test",
    put_data,
    {content_type = "application/x-www-form-urlencoded"}
  )
  if response and response.status then
    return "PUT status=" .. tostring(response.status) .. " body=" .. tostring(response.body)
  end
  return "PUT failed"
end
