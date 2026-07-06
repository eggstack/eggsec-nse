local stdnse = require "stdnse"

description = [[Upstream-style brute force credential shape with proper categories.
Tests the common brute-force script structure without actual network operations.]]

categories = {"auth", "brute"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local userlist = {"admin", "root", "user", "test"}
  local passlist = {"password", "123456", "admin", "root"}

  local attempts = 0
  for _, user in ipairs(userlist) do
    for _, pass in ipairs(passlist) do
      attempts = attempts + 1
    end
  end

  return string.format("Credential matrix: %d users x %d passwords = %d attempts",
    #userlist, #passlist, attempts)
end
