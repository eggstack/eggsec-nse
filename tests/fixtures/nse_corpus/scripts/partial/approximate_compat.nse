local stdnse = require "stdnse"
description = [[Script with approximate compatibility warning.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  stdnse.verbose("Using approximate port matching")
  return "approximate result"
end
