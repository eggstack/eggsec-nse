local socket = require "socket"
local stdnse = require "stdnse"
description = [[UDP send and echo via local fixture server.
Sends a datagram to the local UDP echo server and reads the response.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "udp"
end
action = function(host, port)
  local sock = socket.udp()
  if not sock then
    return "failed to create UDP socket"
  end
  sock:set_timeout(5000)
  socket.sendto(sock, host.ip, port.number, "udp-test")
  local result = socket.receive_from(sock)
  sock:close()
  if result and result.data then
    return "udp echo: " .. result.data
  end
  return "no UDP response"
end
