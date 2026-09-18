"""The checkpoint.

Every tool call an agent makes lands in on_call_tool below, and has to get
past five steps before anything happens:

    1. who is this        verify the agent's SVID
    2. may it do this     ask the policy engine about this exact call
    3. does a human       pause for approval if the rules say so
       need to say yes
    4. mint a key         a token good for this one call and nothing else
    5. write it down      append to the audit log, allowed or refused

Note what is not in the list: asking the model whether it meant to do this.
The model's confidence is not evidence. A call gets through because the rules
say it may, or it does not get through.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from gateway.approval import ApprovalQueue
from gateway.audit import AuditLog
from gateway.identity import InvalidIdentity, TrustDomain
from gateway.policy import Policy, PolicyEngine
from gateway.tokens import TokenService
from gateway.upstream import Upstream
from gateway.wire import SVID_FIELD

logger = logging.getLogger("gateway")

UNKNOWN_AGENT = "unknown"


@dataclass
class Gateway:
    """Everything the checkpoint needs to make a decision."""

    upstream: Upstream
    trust_domain: TrustDomain
    policy: Policy
    tokens: TokenService
    approvals: ApprovalQueue
    audit: AuditLog


def _refuse(reason: str) -> CallToolResult:
    """Tell the agent no, and why.

    The reason goes back deliberately. An agent that knows why it was refused
    can do something sensible instead of retrying forever.
    """
    return CallToolResult(
        content=[TextContent(type="text", text=f"refused: {reason}")], is_error=True
    )


def build_server(gateway: Gateway) -> Server[None]:
    async def on_list_tools(
        ctx: ServerRequestContext[None],
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        return await gateway.upstream.list_tools()

    async def on_call_tool(
        ctx: ServerRequestContext[None],
        params: CallToolRequestParams,
    ) -> CallToolResult:
        tool = params.name
        arguments: dict[str, Any] = dict(params.arguments or {})

        def record(agent: str, outcome: str, reason: str) -> None:
            gateway.audit.append(
                agent=agent, tool=tool, arguments=arguments, outcome=outcome, reason=reason
            )
            logger.info("%s %s -> %s (%s)", agent, tool, outcome, reason)

        # 1. Who is this? An unsigned or expired identity gets no further.
        svid = (params.meta or {}).get(SVID_FIELD)
        if not isinstance(svid, str):
            record(UNKNOWN_AGENT, "deny", "no identity presented")
            return _refuse("no identity presented")

        try:
            agent = gateway.trust_domain.verify_svid(svid)
        except InvalidIdentity as exc:
            record(UNKNOWN_AGENT, "deny", f"bad identity: {exc}")
            return _refuse(f"bad identity: {exc}")

        # 2. May this agent make this exact call, with these exact arguments?
        decision = await gateway.policy.decide(agent, tool, arguments)

        # 3. Some calls are allowed only once a person signs off.
        if decision.outcome == "needs_approval":
            record(agent, "pending", decision.reason)
            approved = await gateway.approvals.ask(agent, tool, arguments, decision.reason)
            if not approved:
                record(agent, "deny", "a human did not approve it")
                return _refuse("a human did not approve it")

        elif decision.outcome != "allow":
            record(agent, "deny", decision.reason)
            return _refuse(decision.reason)

        # 4. Swap the agent's identity for a key that opens this one door.
        token = gateway.tokens.exchange(agent, tool, arguments)

        # 5. Do the call, and write down that it happened.
        result = await gateway.upstream.call_tool(tool, arguments, token)
        record(agent, "allow", decision.reason)
        return result

    @asynccontextmanager
    async def lifespan(_server: Server[None]) -> AsyncIterator[None]:
        await gateway.upstream.start()
        logger.info("connected to tool server")
        try:
            yield None
        finally:
            await gateway.upstream.stop()

    return Server(
        name="agent-authz-gateway",
        version="0.1.0",
        lifespan=lifespan,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_default(audit_path: Any = None) -> Gateway:
    """The wiring used by the demo and the tests."""
    trust_domain = TrustDomain.load_or_create()
    audit = AuditLog(audit_path) if audit_path else AuditLog()
    return Gateway(
        upstream=Upstream(),
        trust_domain=trust_domain,
        policy=PolicyEngine(),
        tokens=TokenService(trust_domain),
        approvals=ApprovalQueue(),
        audit=audit,
    )
