local upnp = require "upnp"
local stdnse = require "stdnse"
description = [[UPnP get_external_ip against local fixture server.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local result = upnp.get_external_ip("http://" .. host.ip .. ":" .. port.number .. "/ipc")
  if result and result.success then
    return "external IP: " .. tostring(result.ip)
  end
  return "upnp get_external_ip failed: " .. tostring(result and result.error or "unknown")
end
