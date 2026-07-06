description = [[Script using postrule for post-scan operations.]]
postrule = function()
  return true
end
action = function(host, port)
  return "postrule executed"
end
