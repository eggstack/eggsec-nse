local stdnse = require "stdnse"
local sslcert = require "sslcert"

description = [[Upstream-style SSL certificate summary script.
Mimics the ssl-cert.nse pattern for certificate information extraction.
Uses sslcert.makecerts() pattern for certificate handling.]]

portrule = function(host, port)
  return sslcert.isPort(port) or (port.protocol == "tcp" and port.service == "https")
end

action = function(host, port)
  -- Simulate certificate summary output
  local subject = "CN=example.com"
  local issuer = "CN=Let's Encrypt Authority X3"
  local valid_from = "Jan  1 00:00:00 2024 GMT"
  local valid_to = "Dec 31 23:59:59 2024 GMT"

  local output = stdnse.format_output("ssl-cert", {
    string.format("Subject: %s", subject),
    string.format("Issuer: %s", issuer),
    string.format("Valid from: %s", valid_from),
    string.format("Valid to: %s", valid_to),
  })

  return output
end
