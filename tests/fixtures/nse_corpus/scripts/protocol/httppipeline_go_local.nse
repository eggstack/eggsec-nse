local httppipeline = require "httppipeline"
local stdnse = require "stdnse"
description = [[httppipeline go against local fixture server.]]
categories = {"discovery", "safe"}
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local pipeline = httppipeline.new(host.ip, port.number)
  httppipeline.add(pipeline, "GET", "/")
  local responses = httppipeline.go(pipeline)
  if responses and responses[1] and responses[1].status then
    return "httppipeline response: status=" .. tostring(responses[1].status)
  end
  return "httppipeline go failed"
end
