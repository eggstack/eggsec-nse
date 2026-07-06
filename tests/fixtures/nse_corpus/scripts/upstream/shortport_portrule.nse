local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[Upstream-style portrule using shortport helper patterns.
Mimics the common shortport.port_or_service() pattern found in many Nmap scripts.]]

-- Shortport-style portrule: matches common HTTP/HTTPS ports
portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https"})

action = function(host, port)
  return "shortport matched: " .. port.service
end
