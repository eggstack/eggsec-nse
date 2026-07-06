local stdnse = require "stdnse"
description = [[Regression: compression bounded path test.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local data = string.rep("A", 1024)
  local compressed = stdnse.compress(data)
  return "compressed " .. #data .. " bytes"
end
