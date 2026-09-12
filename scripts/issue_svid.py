"""Hands the agent its identity.

    uv run python scripts/issue_svid.py

In a real SPIFFE setup a local agent called SPIRE does this: a workload starts
up, asks for its identity over a socket, and gets back a short-lived document
it did not have to store a password for. This script is the same idea with the
networking removed. It writes the SVID to a file the agent reads.

The identity expires in five minutes on purpose. Run it again if the demo has
been sitting idle.
"""

from pathlib import Path

from gateway.identity import KEY_DIR, TrustDomain

SVID_PATH = KEY_DIR / "agent.svid"
WORKLOAD = "agent/summarizer"


def main() -> None:
    trust_domain = TrustDomain.load_or_create()
    svid = trust_domain.issue_svid(WORKLOAD)

    Path(SVID_PATH).write_text(svid)
    print(f"issued an identity for spiffe://demo.local/{WORKLOAD}")
    print(f"written to {SVID_PATH}, valid for 5 minutes")


if __name__ == "__main__":
    main()
