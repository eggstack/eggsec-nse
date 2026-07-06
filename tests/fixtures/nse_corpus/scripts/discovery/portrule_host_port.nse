description = [[Tests portrule receives (host, port) arguments with context fidelity.]]
categories = {"discovery"}
portrule = function(host, port)
  return host.ip ~= nil and port.number ~= nil and port.protocol == "tcp"
end
action = function(host, port)
  return "host=" .. (host.ip or "nil") .. " port=" .. tostring(port.number)
end
