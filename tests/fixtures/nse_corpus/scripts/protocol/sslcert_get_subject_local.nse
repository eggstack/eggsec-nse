local sslcert = require "sslcert"
description = [[Certificate subject extraction test against local TLS server]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local cert = sslcert.get_certificate(host.ip, port.number)
  if cert.error then
    return "ERROR: " .. cert.error
  end
  local subject = sslcert.get_subject(cert)
  local parts = {}
  if subject.subject then table.insert(parts, "subject=" .. subject.subject) end
  return "sslcert.get_subject: " .. table.concat(parts, ", ")
end
