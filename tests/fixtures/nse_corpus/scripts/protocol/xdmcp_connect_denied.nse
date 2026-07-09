local xdmcp = require "xdmcp"
local stdnse = require "stdnse"
description = [[XDMCP connect that should be denied under AgentSafe profile.
Calls xdmcp.connect against a local TCP server; the capability gate should
block the connection before any socket I/O occurs.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local result = xdmcp.connect(host.ip, port.number)
  if type(result) ~= "table" then
    return "xdmcp.connect returned non-table: " .. tostring(result)
  end
  local status = result.status or "(none)"
  local err = result.error or "(none)"
  return string.format("xdmcp.connect status=%s error=%s", status, err)
end