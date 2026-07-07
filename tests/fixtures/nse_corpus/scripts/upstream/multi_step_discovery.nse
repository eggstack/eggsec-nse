local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Upstream-style multi-step discovery script.
Chains multiple library calls: nmap.get_ports(), stdnse.output_table(), string formatting.
Tests common orchestration patterns in NSE scripts.]]

categories = {"discovery", "safe"}

hostrule = function(host)
  return host ~= nil
end

action = function(host)
  local result = stdnse.output_table()
  result["host"] = host.ip or "unknown"
  result["hostname"] = host.hostname or "unknown"
  result["status"] = "discovered"
  result["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
  return result
end
