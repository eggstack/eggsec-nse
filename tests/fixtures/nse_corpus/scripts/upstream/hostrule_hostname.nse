local stdnse = require "stdnse"

description = [[Upstream-style hostrule matching on hostname patterns.
Tests hostname-based rule evaluation common in discovery scripts.]]

categories = {"discovery"}

hostrule = function(host)
  local name = host.hostname or ""
  -- Match common internal hostnames
  return string.match(name, "^db%-") or string.match(name, "^web%-") or string.match(name, "^app%-")
end

action = function(host)
  return "hostrule matched hostname: " .. (host.hostname or "unknown")
end
