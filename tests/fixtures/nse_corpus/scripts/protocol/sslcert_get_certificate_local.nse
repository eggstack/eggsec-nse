local sslcert = require "sslcert"
description = [[TLS certificate retrieval against local TLS server]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local cert = sslcert.get_certificate(host.ip, port.number)
  if cert.error then
    return "ERROR: " .. cert.error
  end
  local parts = {}
  if cert.subject then table.insert(parts, "subject=" .. cert.subject) end
  if cert.issuer then table.insert(parts, "issuer=" .. cert.issuer) end
  if cert.version then table.insert(parts, "version=" .. cert.version) end
  return "sslcert.get_certificate: " .. table.concat(parts, ", ")
end
