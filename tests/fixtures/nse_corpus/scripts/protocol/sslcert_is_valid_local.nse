local sslcert = require "sslcert"
description = [[Certificate validity check test against local TLS server]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local cert = sslcert.get_certificate(host.ip, port.number)
  if cert.error then
    return "ERROR: " .. cert.error
  end
  local validity = sslcert.is_valid(cert)
  local parts = {}
  if validity.valid ~= nil then table.insert(parts, "valid=" .. tostring(validity.valid)) end
  if validity.notbefore then table.insert(parts, "notbefore=" .. validity.notbefore) end
  if validity.notafter then table.insert(parts, "notafter=" .. validity.notafter) end
  return "sslcert.is_valid: " .. table.concat(parts, ", ")
end
