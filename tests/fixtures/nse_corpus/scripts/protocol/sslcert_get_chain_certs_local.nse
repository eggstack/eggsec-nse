local sslcert = require "sslcert"
description = [[Certificate chain retrieval test against local TLS server]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local chain = sslcert.get_chain_certs(host.ip, port.number)
  if chain.error then
    return "ERROR: " .. chain.error
  end
  local count = 0
  if chain.certs then
    for i, c in pairs(chain.certs) do
      count = count + 1
    end
  end
  return "sslcert.get_chain_certs: chain_count=" .. count
end
