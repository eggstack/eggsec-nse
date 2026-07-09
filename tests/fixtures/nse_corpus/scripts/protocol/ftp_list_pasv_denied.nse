local ftp = require "ftp"
local stdnse = require "stdnse"
description = [[FTP list that should be denied at the data connection under
strict profiles. The control connection may complete (USER/PASS/PASV), but
the PASV data-connection capability check fires inside ftp.list and the
return is an error table without opening a TCP data socket.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local result = ftp.list(host.ip, port.number, ".")
  if type(result) ~= "table" then
    return "ftp.list returned non-table: " .. tostring(result)
  end
  local status = result.status or "(none)"
  local err = result.error or "(none)"
  local count = result.count or "(none)"
  return string.format("ftp.list status=%s count=%s error=%s", status, tostring(count), err)
end