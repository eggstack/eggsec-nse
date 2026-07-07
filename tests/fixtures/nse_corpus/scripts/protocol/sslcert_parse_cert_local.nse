local sslcert = require "sslcert"
description = [[Certificate PEM parsing test against local TLS server]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local cert = sslcert.get_certificate(host.ip, port.number)
  if cert.error then
    return "ERROR: " .. cert.error
  end
  local parsed = sslcert.parse_cert(cert.pem)
  if parsed.error then
    return "PARSE ERROR: " .. parsed.error
  end
  local parts = {}
  if parsed.subject then table.insert(parts, "subject=" .. parsed.subject) end
  if parsed.issuer then table.insert(parts, "issuer=" .. parsed.issuer) end
  if parsed.fingerprint then table.insert(parts, "fingerprint=" .. string.sub(parsed.fingerprint, 1, 16) .. "...") end
  return "sslcert.parse_cert: " .. table.concat(parts, ", ")
end
