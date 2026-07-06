local stdnse = require "stdnse"
description = [[Service version detection pattern.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local version = stdnse.get_script_args(SCRIPT_NAME .. ".version") or "1.0.0"
  stdnse.verbose("Detected version: %s", version)
  return version
end
