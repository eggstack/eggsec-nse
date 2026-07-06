local stdnse = require "stdnse"
description = [[Test script using stdnse output functions.]]

portrule = function(host, port)
  return port.protocol == "tcp"
end

action = function(host, port)
  local result = stdnse.format_output("test-output", "value")
  return result
end
