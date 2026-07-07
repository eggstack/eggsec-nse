local socket = require "socket"
local stdnse = require "stdnse"
description = [[TCP connect and echo via local fixture server.
Connects to the local TCP echo server, sends a line, reads the response.]]
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
    return "connect failed: " .. tostring(err)
  end
  sock:send("hello from nse\n")
  local result = sock:receive()
  sock:close()
  if result and result.data then
    return "tcp echo: " .. result.data
  end
  return "no response"
end
