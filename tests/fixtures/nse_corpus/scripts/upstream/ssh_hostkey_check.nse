local ssh = require "ssh"
local stdnse = require "stdnse"

description = [[Upstream-style SSH host key verification pattern.
Tests the common ssh.connect() / hostkey check pattern used in NSE scripts.]]

categories = {"auth", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.number == 22 and port.state == "open"
end

action = function(host, port)
  local status, err = ssh.connect(host.ip, port.number)
  if not status then
    return string.format("SSH connection failed: %s", tostring(err))
  end
  return "SSH hostkey check completed"
end
