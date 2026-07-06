description = [[Simple hostrule test script.]]

hostrule = function(host)
  return host.host_state == "up"
end

action = function(host)
  return "hostrule success"
end
