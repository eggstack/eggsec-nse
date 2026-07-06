local stdnse = require "stdnse"

description = [[Upstream-style script producing XML-like structured output.
Tests the common pattern of building XML output tables in NSE scripts.]]

categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local output = stdnse.output_table()
  output.name = "test-result"
  output.type = "structured"
  output.host = host.ip
  output.port = port.number

  local result = {}
  result["key1"] = "value1"
  result["key2"] = "value2"
  output.data = result

  return output
end
