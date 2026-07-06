local vulns = require "vulns"
local stdnse = require "stdnse"

description = [[Upstream-style vulnerability check pattern using the vulns library.
Mimics the common vulns.Report / Vulnerability:new pattern for CVE reporting.]]

categories = {"vuln"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local vuln = vulns.Vulnerability:new(
    "CVE-2024-0001",
    vulns.STATUS.NOT_VULN,
    "Test vulnerability check",
    "This is a test fixture"
  )
  local report = vulns.Report:new("test-vuln-check", host, port)
  report:add_vuln(host, port, vuln)
  return report:generate()
end
