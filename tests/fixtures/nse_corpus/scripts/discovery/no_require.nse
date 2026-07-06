description = [[Script with no require statements.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  return "no-require output"
end
