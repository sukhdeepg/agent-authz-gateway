"""Asks OPA whether a tool call is allowed.

OPA (Open Policy Agent) is a small server that holds the rules and answers
yes/no questions about them. The rules live in policies/authz.rego.

Keeping the rules out of this file is the point. Someone reviewing what the
agent may do reads one .rego file instead of hunting through Python, and the
rules can be tested on their own.
"""

from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpx

OPA_URL = "http://localhost:8181/v1/data/authz/result"

Outcome = Literal["allow", "deny", "needs_approval"]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


class Policy(Protocol):
    """Anything that can answer "may this call happen".

    The gateway depends on this shape rather than on OPA, so tests can swap in
    a fixed answer and test the gateway wiring without a policy server running.
    The rules themselves are tested separately with `opa test`.
    """

    async def decide(self, agent: str, tool: str, arguments: dict[str, Any]) -> Decision: ...


@dataclass
class PolicyEngine:
    url: str = OPA_URL
    timeout: float = 5.0

    async def decide(self, agent: str, tool: str, arguments: dict[str, Any]) -> Decision:
        """Ask OPA about one specific call.

        If OPA is unreachable or gives an answer we do not understand, the
        result is deny. That direction matters: a broken policy server must
        not turn into a gateway that waves everything through.
        """
        request = {"input": {"agent": agent, "tool": tool, "arguments": arguments}}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, json=request)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            return Decision("deny", f"could not reach the policy engine: {exc}")

        result = body.get("result")
        if not isinstance(result, dict):
            return Decision("deny", "policy engine returned no decision")

        outcome = result.get("decision")
        if outcome not in ("allow", "deny", "needs_approval"):
            return Decision("deny", f"policy engine returned an unknown decision: {outcome!r}")

        return Decision(outcome, str(result.get("reason", "")))
