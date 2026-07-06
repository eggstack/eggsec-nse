local stdnse = require "stdnse"

description = [[Upstream-style script demonstrating multiple category tags.
Many Nmap scripts declare categories for organizational purposes.
This fixture tests that category arrays are parsed correctly.]]

categories = {"discovery", "safe", "default"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  return "multi-category script executed"
end
