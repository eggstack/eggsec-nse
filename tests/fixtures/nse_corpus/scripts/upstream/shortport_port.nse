local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[Upstream-style script using shortport.port() for port matching.
Tests the simplest shortport pattern for port number matching.]]

categories = {"discovery", "safe", "default"}

portrule = shortport.port({22, 23, 25, 53, 80, 443, 3306, 5432, 8080})

action = function(host, port)
  return "shortport.port matched: " .. tostring(port.number)
end
