local nmap = require "nmap"
description = [[Simple portrule test script.]]

-- Test portrule using shortport-like pattern
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  return "portrule success"
end
