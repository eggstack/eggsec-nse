description = [[Tests hostrule receives host table with ip and context metadata.]]
categories = {"discovery"}
hostrule = function(host)
  return host.ip ~= nil
end
action = function(host)
  return "host=" .. (host.ip or "nil") .. " source=" .. (host.eggsec_context_source or "nil")
end
