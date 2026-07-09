local ftp = require "ftp"
local stdnse = require "stdnse"
description = [[FTP connect against local fixture server.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local result = ftp.connect(host.ip, port.number)
  if result and result.status == "connected" then
    return "ftp connected: " .. tostring(result.welcome)
  end
  return "ftp connect failed: " .. tostring(result and result.error or "unknown")
end
