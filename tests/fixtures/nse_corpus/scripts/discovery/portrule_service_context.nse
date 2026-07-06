description = [[Tests portrule receives port with service context sub-table.]]
categories = {"discovery"}
portrule = function(host, port)
  return port.number ~= nil and port.service ~= nil
end
action = function(host, port)
  local svc_name = port.service and port.service.name or "unknown"
  return "port=" .. tostring(port.number) .. " service=" .. svc_name
end
