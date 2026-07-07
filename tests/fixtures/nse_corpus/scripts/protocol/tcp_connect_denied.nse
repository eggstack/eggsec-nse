local socket = require "socket"
local stdnse = require "stdnse"
description = [[TCP connect that should be denied under AgentSafe profile.
Uses socket.tcp() to attempt a connection that the capability context should block.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local sock = socket.tcp()
  if not sock then
    return "failed to create socket"
  end
  local status, err = sock:connect(host.ip, port.number)
  if not status then
    return "connect denied: " .. tostring(err)
  end
  sock:send("should-not-succeed\n")
  local result = sock:receive()
  sock:close()
  if result and result.data then
    return "tcp unexpected success: " .. result.data
  end
  return "no response (may be denied)"
end
