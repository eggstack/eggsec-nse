description = [[Script where portrule throws an error.]]
portrule = function(host, port)
  error("intentional portrule error")
end
action = function(host, port)
  return "should not execute"
end
