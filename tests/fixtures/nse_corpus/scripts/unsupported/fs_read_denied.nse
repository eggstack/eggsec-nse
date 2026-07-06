local stdnse = require "stdnse"
description = [[Script requiring filesystem read outside allowed directory.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local f = io.open("/etc/passwd", "r")
  if f then
    local content = f:read("*all")
    f:close()
    return content
  end
  return "file read failed"
end
