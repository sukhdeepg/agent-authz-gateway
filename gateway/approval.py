"""Pauses a risky call until a person says yes.

Some actions should not happen on a model's say-so, however confident it is.
When policy answers "needs_approval", the call stops here and waits.

The queue is in memory, which is fine because a pending approval is only
meaningful while the call it belongs to is still waiting. Restart the gateway
and every waiting call is gone anyway.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class Request:
    """One call sitting in the queue waiting for a human."""

    id: str
    agent: str
    tool: str
    arguments: dict[str, Any]
    reason: str
    decided: asyncio.Event = field(default_factory=asyncio.Event)
    approved: bool = False

    def describe(self) -> str:
        return f"[{self.id}] {self.agent} wants to call {self.tool} with {self.arguments}"


@dataclass
class ApprovalQueue:
    """Holds pending requests and wakes them up once someone decides."""

    timeout_seconds: float = 60.0
    pending: dict[str, Request] = field(default_factory=dict)

    async def ask(self, agent: str, tool: str, arguments: dict[str, Any], reason: str) -> bool:
        """Block until a person approves or denies, or until we give up waiting.

        Timing out counts as a no. If nobody is around to approve a risky
        action, the safe thing is for it not to happen.
        """
        request = Request(
            id=uuid4().hex[:8],
            agent=agent,
            tool=tool,
            arguments=arguments,
            reason=reason,
        )
        self.pending[request.id] = request
        try:
            await asyncio.wait_for(request.decided.wait(), timeout=self.timeout_seconds)
        except TimeoutError:
            return False
        finally:
            self.pending.pop(request.id, None)
        return request.approved

    def resolve(self, request_id: str, approved: bool) -> bool:
        """Called by whoever is reviewing. Returns False if the id is unknown."""
        request = self.pending.get(request_id)
        if request is None:
            return False
        request.approved = approved
        request.decided.set()
        return True

    def waiting(self) -> list[Request]:
        return list(self.pending.values())
