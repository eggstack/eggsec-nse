description = [[Script where portrule always returns false.]]
portrule = function(host, port)
  return false
end
action = function(host, port)
  return "should not execute"
end
