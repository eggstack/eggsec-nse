local stdnse = require "stdnse"

description = [[Upstream-style conditional portrule with argument checking.
Tests common NSE patterns: SCRIPT_NAME, script args, table lookups,
and conditional portrule logic.]]

categories = {"safe", "discovery"}

portrule = function(host, port)
  local arg = stdnse.get_script_args(SCRIPT_NAME .. ".port") or "80"
  local target_port = tonumber(arg) or 80
  return port.protocol == "tcp" and port.number == target_port and port.state == "open"
end

action = function(host, port)
  local arg = stdnse.get_script_args(SCRIPT_NAME .. ".mode") or "default"
  return string.format("Conditional match on port %d, mode: %s", port.number, arg)
end
