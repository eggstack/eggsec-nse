local stdnse = require "stdnse"

description = [[Upstream-style script producing structured output using stdnse output helpers.
Tests the common pattern of building tabular output for NSE scripts.]]

categories = {"default", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp"
end

action = function(host, port)
  local output = {}
  output["Host"] = host.ip
  output["Port"] = tostring(port.number)
  output["Protocol"] = port.protocol
  output["State"] = port.state
  output["Service"] = port.service

  local result = stdnse.format_output(output, true)
  return result
end
