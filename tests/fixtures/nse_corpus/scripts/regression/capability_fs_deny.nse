local stdnse = require "stdnse"
description = [[Regression: capability event for filesystem read denial.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local f = io.open("/etc/shadow", "r")
  if f then
    f:close()
    return "should not read"
  end
  return "filesystem read denied"
end
