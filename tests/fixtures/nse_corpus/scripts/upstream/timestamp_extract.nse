local stdnse = require "stdnse"

description = [[Upstream-style timestamp extraction and formatting pattern.
Tests common NSE patterns for time-based logging and structured output
using os.date() and stdnse output helpers.]]

categories = {"safe", "default"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local output = stdnse.output_table()
  output["scan_time"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
  output["target"] = host.ip
  output["port"] = port.number
  output["service"] = port.service or "unknown"
  return output
end
