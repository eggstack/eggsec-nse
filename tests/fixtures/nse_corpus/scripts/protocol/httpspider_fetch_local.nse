local httpspider = require "httpspider"
local stdnse = require "stdnse"
description = [[httpspider fetch against local fixture server.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local url = "http://" .. host.ip .. ":" .. port.number .. "/"
  local result = httpspider.fetch(url)
  if result and result.status == 200 then
    return "httpspider fetched: status=" .. tostring(result.status)
  end
  return "httpspider fetch failed: " .. tostring(result and result.error or "unknown")
end
