local http = require "http"
local stdnse = require "stdnse"

description = [[Upstream-style HTTP POST request pattern.
Mimics common http.post() usage for API endpoint testing.]]

categories = {"intrusive", "vuln"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.service == "http"
end

action = function(host, port)
  local post_data = stdnse.output_table()
  post_data["action"] = "test"
  post_data["target"] = host.ip

  local response = http.post(
    "http://" .. host.ip .. ":" .. port.number .. "/api/test",
    {
      content_type = "application/x-www-form-urlencoded",
      header = "X-Test-Header: eggsec",
    },
    nil,
    post_data
  )

  if response and response.status then
    return "POST response: " .. tostring(response.status)
  end
  return "POST request failed"
end
