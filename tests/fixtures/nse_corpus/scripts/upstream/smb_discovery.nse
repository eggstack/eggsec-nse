local smb = require "smb"
local stdnse = require "stdnse"

description = [[Upstream-style SMB discovery pattern.
Tests the common smb.start() / smb.get_server_info() pattern.]]

categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.number == 445 and port.state == "open"
end

action = function(host, port)
  local status, err = smb.start(host.ip, port)
  if not status then
    return string.format("SMB connection failed: %s", tostring(err))
  end
  return "SMB discovery completed"
end
