"""Who is this agent, and can it prove it?

An API key answers "who are you" with a shared secret. Anyone who copies the
string becomes you, it never expires, and it says nothing about what you are.

SPIFFE does it differently. Every workload gets a name that looks like a URL:

    spiffe://demo.local/agent/summarizer
    \\_____/  \\________/ \\______________/
     scheme   trust domain    the workload

and a short-lived credential proving it holds that name. This file issues and
verifies the JWT flavour of that credential, called a JWT-SVID.

The important part is who can do what:

  * the trust domain holds the private key, so only it can mint an identity
  * everyone else holds the public key, so anyone can check one
  * the credential expires in minutes, so a copied one is quickly worthless

A stolen API key is a problem for as long as nobody notices. A stolen SVID is
a problem until it expires.
"""

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

TRUST_DOMAIN = "demo.local"

# Where the signing key lives. The tool server runs as a separate process and
# has to look in the same place, so this is settable from the environment.
KEY_DIR = Path(os.environ.get("AUTHZ_CERT_DIR", "certs"))

SVID_TTL = timedelta(minutes=5)

# Who the SVID is meant for. A credential minted for the gateway should not be
# replayable somewhere else, so the audience is checked on the way in.
GATEWAY_AUDIENCE = "gateway"


class InvalidIdentity(Exception):
    """The SVID was missing, expired, tampered with, or meant for someone else."""


def spiffe_id(workload: str) -> str:
    """Build a SPIFFE ID, e.g. spiffe_id("agent/summarizer")."""
    return f"spiffe://{TRUST_DOMAIN}/{workload.lstrip('/')}"


@dataclass
class TrustDomain:
    """Holds the signing key for one trust domain."""

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def load_or_create(cls, directory: Path = KEY_DIR) -> "TrustDomain":
        """Load the signing key, generating one the first time.

        A real deployment gets this from SPIRE and rotates it. A file on disk
        is the shortest thing that behaves the same way.
        """
        directory.mkdir(parents=True, exist_ok=True)
        key_file = directory / "trust-domain.key"

        if key_file.exists():
            loaded = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
            assert isinstance(loaded, ec.EllipticCurvePrivateKey)
            return cls(loaded)

        key = ec.generate_private_key(ec.SECP256R1())
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_file.chmod(0o600)
        return cls(key)

    @property
    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def issue_svid(self, workload: str, ttl: timedelta = SVID_TTL) -> str:
        """Mint a short-lived identity document for one workload."""
        now = datetime.now(UTC)
        claims = {
            "sub": spiffe_id(workload),
            "aud": GATEWAY_AUDIENCE,
            "iat": now,
            "exp": now + ttl,
        }
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(claims, private_pem, algorithm="ES256")

    def verify_svid(self, token: str, audience: str = GATEWAY_AUDIENCE) -> str:
        """Check an SVID and return the SPIFFE ID inside it.

        Raises InvalidIdentity if anything is off. There is no "probably fine"
        branch here, because a maybe-valid identity is just an invalid one.
        """
        try:
            claims = jwt.decode(
                token,
                self.public_pem,
                algorithms=["ES256"],
                audience=audience,
            )
        except jwt.PyJWTError as exc:
            raise InvalidIdentity(str(exc)) from exc

        subject = claims.get("sub", "")
        if not subject.startswith(f"spiffe://{TRUST_DOMAIN}/"):
            raise InvalidIdentity(f"{subject!r} is not an identity from this trust domain")
        return str(subject)
