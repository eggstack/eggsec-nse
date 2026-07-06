description = [[Script using prerule for pre-scan operations.]]
prerule = function()
  return true
end
action = function(host, port)
  return "prerule executed"
end
