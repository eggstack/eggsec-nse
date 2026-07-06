local stdnse = require "stdnse"

description = [[Upstream-style script using SCRIPT_NAME and script args.
Tests the common pattern of reading script-specific arguments via stdnse.get_script_args().]]

portrule = function(host, port)
  return port.protocol == "tcp"
end

action = function(host, port)
  local user_agent = stdnse.get_script_args(SCRIPT_NAME .. ".useragent") or "NSE-Script"
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10

  stdnse.verbose("User agent: %s, Timeout: %d", user_agent, timeout)
  return string.format("args: useragent=%s timeout=%d", user_agent, timeout)
end
