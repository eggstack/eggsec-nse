local stdnse = require "stdnse"
description = [[Script requiring process execution - denied by AgentSafe.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local handle = io.popen("echo hello")
  local result = handle:read("*a")
  handle:close()
  return result
end
