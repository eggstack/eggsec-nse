local dhcp = require "dhcp"
local stdnse = require "stdnse"
description = [[DHCP discover that should be denied under AgentSafe profile.
Calls dhcp.discover against a local UDP server; the capability gate should
block the sendto before any UDP packet is transmitted.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "udp"
end
action = function(host, port)
  local result = dhcp.discover(host.ip, "00:11:22:33:44:55")
  if type(result) ~= "table" then
    return "dhcp.discover returned non-table: " .. tostring(result)
  end
  local status = result.status or "(none)"
  local err = result.error or "(none)"
  return string.format("dhcp.discover status=%s error=%s", status, err)
end