description = [[Test script that requires a builtin module.]]

portrule = function(host, port)
  return port.protocol == "tcp"
end

action = function(host, port)
  local ok, err = pcall(require, "stdnse")
  if ok then
    return "builtin module loaded"
  else
    return "builtin module load failed: " .. tostring(err)
  end
end
