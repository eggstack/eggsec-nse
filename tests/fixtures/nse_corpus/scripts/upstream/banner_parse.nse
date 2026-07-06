local stdnse = require "stdnse"

description = [[Upstream-style script using string patterns for response parsing.
Tests the common Lua string matching pattern used in NSE scripts for banner/service detection.]]

categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  -- Simulate banner parsing pattern
  local banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
  local version = string.match(banner, "SSH%-([%d%.]+)")
  local software = string.match(banner, "SSH%-[%d%.]+%s+(.+)$")

  if version then
    return string.format("SSH version: %s, software: %s", version, software or "unknown")
  end
  return "no SSH banner detected"
end
