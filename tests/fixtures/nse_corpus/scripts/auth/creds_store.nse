local stdnse = require "stdnse"
local creds = require "creds"
description = [[Tests the creds library credential storage and retrieval.]]
categories = {"auth", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local c = creds.new("ssh", "open")
  c.user = "admin"
  c.pass = "secret123"
  creds.add(nil, "ssh", "admin", "secret123", "open")
  creds.add(nil, "http", "user", "pass456", "open")
  local result = creds.get(nil, "ssh")
  local usernames = creds.get_username(nil)
  local passwords = creds.get_password(nil)
  local all = creds.dump()
  local count = 0
  for _ in pairs(all) do count = count + 1 end
  return string.format("stored=%d users=%d passwords=%d ssh_entries=%d", count, #usernames, #passwords, #result)
end
