local stdnse = require "stdnse"
description = [[Credential shape test - no real brute force.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local users = {"admin", "root", "test"}
  local passwords = {"password123", "admin", "root"}
  local count = 0
  for _, user in ipairs(users) do
    for _, pass in ipairs(passwords) do
      count = count + 1
    end
  end
  return "tested " .. count .. " credential pairs (dry run)"
end
