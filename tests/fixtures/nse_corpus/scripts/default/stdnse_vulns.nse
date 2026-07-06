local stdnse = require "stdnse"
local vulns = require "vulns"
description = [[Script requiring stdnse and vulns libraries.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local vuln = vulns.Vulnerability:new("TEST-001", vulns.STATUS.NOT_VULN)
  return "vulns library loaded"
end
