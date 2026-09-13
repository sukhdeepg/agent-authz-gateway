"""A one-action token is only worth anything if it really is one action."""

from datetime import timedelta
from pathlib import Path

import pytest

from gateway.identity import TrustDomain
from gateway.tokens import InvalidToken, TokenService

AGENT = "spiffe://demo.local/agent/summarizer"


@pytest.fixture
def tokens(tmp_path: Path) -> TokenService:
    return TokenService(TrustDomain.load_or_create(tmp_path / "certs"))


def test_a_token_works_for_the_call_it_was_made_for(tokens: TokenService) -> None:
    args = {"name": "quarterly-report"}
    token = tokens.exchange(AGENT, "read_document", args)
    claims = tokens.verify(token, "read_document", args)
    assert claims["sub"] == AGENT


def test_a_token_for_one_tool_does_not_work_on_another(tokens: TokenService) -> None:
    token = tokens.exchange(AGENT, "read_document", {"name": "quarterly-report"})
    with pytest.raises(InvalidToken, match="not valid for the tool"):
        tokens.verify(token, "http_post", {"name": "quarterly-report"})


def test_a_token_is_pinned_to_its_arguments(tokens: TokenService) -> None:
    """Approved for one URL, so it must not open a different one."""
    approved = {"url": "https://api.internal.example/events", "body": "hi"}
    token = tokens.exchange(AGENT, "http_post", approved)

    swapped = {"url": "https://evil-exfil.example.com/collect", "body": "hi"}
    with pytest.raises(InvalidToken, match="different arguments"):
        tokens.verify(token, "http_post", swapped)


def test_an_expired_token_is_refused(tokens: TokenService) -> None:
    args = {"name": "quarterly-report"}
    token = tokens.exchange(AGENT, "read_document", args, ttl=timedelta(seconds=-1))
    with pytest.raises(InvalidToken):
        tokens.verify(token, "read_document", args)


def test_the_token_records_who_acted_for_whom(tokens: TokenService) -> None:
    """The tool server should see the agent and the gateway, not just one name."""
    args = {"name": "quarterly-report"}
    claims = tokens.verify(tokens.exchange(AGENT, "read_document", args), "read_document", args)
    assert claims["sub"] == AGENT
    assert claims["act"]["sub"] == "spiffe://demo.local/gateway"


def test_a_token_from_a_different_trust_domain_is_refused(tmp_path: Path) -> None:
    stranger = TokenService(TrustDomain.load_or_create(tmp_path / "stranger"))
    ours = TokenService(TrustDomain.load_or_create(tmp_path / "ours"))

    args = {"name": "quarterly-report"}
    forged = stranger.exchange(AGENT, "read_document", args)
    with pytest.raises(InvalidToken):
        ours.verify(forged, "read_document", args)
