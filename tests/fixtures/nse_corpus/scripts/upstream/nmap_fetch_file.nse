local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[Upstream-style script using nmap nmap.fetch_file() for local file operations.
Tests the common nmap utility function pattern.]]

categories = {"safe", "default"}

portrule = function(host, port)
  return port.protocol == "tcp"
end

action = function(host, port)
  -- Simulate fetch_file pattern without actual filesystem access
  local datafile = SCRIPT_NAME .. ".dat"
  stdnse.verbose("Would fetch file: %s", datafile)
  return "nmap.fetch_file pattern tested: " .. datafile
end
