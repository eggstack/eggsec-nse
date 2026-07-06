local dns = require "dns"
local stdnse = require "stdnse"

description = [[Upstream-style DNS reverse lookup pattern.
Mimics the common dns.reverse() pattern for PTR record resolution.]]

categories = {"discovery", "safe"}

portrule = function(host, port)
  return true
end

action = function(host, port)
  local status, result = dns.reverse(host.ip)
  if status then
    return "Reverse DNS: " .. tostring(result)
  else
    return "Reverse DNS lookup failed: " .. tostring(result)
  end
end
