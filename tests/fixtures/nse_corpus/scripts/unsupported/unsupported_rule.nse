description = [[Script with non-boolean portrule return value.]]
portrule = function(host, port)
  return "yes"
end
action = function(host, port)
  return "should not reach here"
end
