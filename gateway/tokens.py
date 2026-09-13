"""Turns "this agent is allowed to do this" into a key that opens exactly that.

The agent never holds a credential for the tool server. It holds an identity
(its SVID), which proves who it is and nothing more. When a call is approved,
the gateway swaps that identity for a token good for one specific action:

    subject token  ->  gateway  ->  access token
    "I am the          checks       "the bearer may call http_post
     summarizer"       policy        with exactly these arguments,
                                     for the next 30 seconds"

This swap is OAuth 2.0 Token Exchange, RFC 8693. The claim that matters is
`act`, short for actor: it records that the gateway performed this on behalf
of the agent, so the tool server sees the whole chain rather than one identity
standing in for everyone.

Why bother, when the gateway could just call the tool directly? Because a
leaked token should be worthless. This one names a single tool, is pinned to
the exact arguments, and expires before anyone could use it twice.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization

from gateway.identity import TrustDomain

ACTION_TOKEN_TTL = timedelta(seconds=30)
TOOLSERVER_AUDIENCE = "toolserver"
GATEWAY_ID = "spiffe://demo.local/gateway"


class InvalidToken(Exception):
    """The token was missing, expired, or does not match the call being made."""


def bind_arguments(arguments: dict[str, Any]) -> str:
    """Fingerprint the arguments so the token cannot be reused on a different call.

    Without this, a token for "post to the approved host" could be replayed to
    post somewhere else. The tool server recomputes this hash and refuses if it
    does not match what it was actually asked to do.
    """
    body = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


@dataclass
class TokenService:
    """Mints and checks single-action tokens."""

    trust_domain: TrustDomain

    def _private_pem(self) -> bytes:
        return self.trust_domain.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def exchange(
        self,
        subject: str,
        tool: str,
        arguments: dict[str, Any],
        ttl: timedelta = ACTION_TOKEN_TTL,
    ) -> str:
        """Swap a verified identity for a token that only opens one door."""
        now = datetime.now(UTC)
        claims = {
            "sub": subject,
            "aud": TOOLSERVER_AUDIENCE,
            "iat": now,
            "exp": now + ttl,
            "scope": f"tool:{tool}",
            "args": bind_arguments(arguments),
            # The delegation chain: the gateway acted for the agent.
            "act": {"sub": GATEWAY_ID},
        }
        return jwt.encode(claims, self._private_pem(), algorithm="ES256")

    def verify(self, token: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Check a token really covers the call being attempted."""
        try:
            claims = jwt.decode(
                token,
                self.trust_domain.public_pem,
                algorithms=["ES256"],
                audience=TOOLSERVER_AUDIENCE,
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(str(exc)) from exc

        if claims.get("scope") != f"tool:{tool}":
            raise InvalidToken(f"token is not valid for the tool {tool}")

        if claims.get("args") != bind_arguments(arguments):
            raise InvalidToken("token was minted for different arguments")

        return dict(claims)
