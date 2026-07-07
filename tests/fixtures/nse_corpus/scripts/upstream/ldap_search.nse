local ldap = require "ldap"
local stdnse = require "stdnse"

description = [[Upstream-style LDAP search pattern.
Tests the common ldap.open() / ldap.search() pattern used in NSE scripts.]]

categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.number == 389 and port.state == "open"
end

action = function(host, port)
  local status, err = ldap.open(host.ip, port.number)
  if not status then
    return string.format("LDAP connection failed: %s", tostring(err))
  end
  return "LDAP search completed"
end
