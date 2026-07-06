local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[Upstream-style portrule using shortport helper patterns.
Demonstrates a clean-room portrule that matches HTTP ports using a
manual inline check that mirrors the intent of shortport.port_or_service
without requiring the helper to be exposed by eggsec's shortport library.]]

-- Inline portrule matching HTTP-like ports (mimics shortport.port_or_service semantics)
portrule = function(host, port)
  local http_ports = { [80]=true, [443]=true, [8080]=true, [8443]=true }
  return port.protocol == "tcp" and http_ports[port.number] == true
end

action = function(host, port)
  return "shortport-style matched: " .. tostring(port.number)
end