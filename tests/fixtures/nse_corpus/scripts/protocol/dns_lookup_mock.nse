local dns = require "dns"
local stdnse = require "stdnse"
description = [[DNS lookup pattern with mock deny path.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local status, result = dns.query("example.com")
  if status then
    return "resolved: " .. tostring(result)
  else
    return "dns query failed: " .. tostring(result)
  end
end
