description = [[This script should be denied by AgentSafe policy.]]

portrule = function(host, port)
  return port.protocol == "tcp"
end

action = function(host, port)
  return "should not execute under agent-safe"
end
