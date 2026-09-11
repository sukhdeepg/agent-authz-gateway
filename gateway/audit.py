"""Append-only log where each line is chained to the one before it.

Why bother chaining? A plain log file is easy to doctor. Anyone who can write
to the file can go back and quietly change what happened, or delete the line
that embarrasses them.

The trick here is simple. Every line stores a hash of itself plus the hash of
the previous line, like links in a chain:

    line 1   hash = H("" + line1)
    line 2   hash = H(hash1 + line2)
    line 3   hash = H(hash2 + line3)

Change anything in line 2 and its hash no longer matches, and because line 3
was built on top of line 2's hash, every line after it breaks too. You cannot
fix one line without rewriting the whole file from that point on.

This does not make the log impossible to tamper with. It makes tampering
impossible to hide, which is the thing you actually want.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_PATH = Path("audit.jsonl")

# The hash the very first line chains onto. Any fixed value works, it just
# has to be the same every time so verification can reproduce it.
GENESIS = "0" * 64


def _fingerprint(previous_hash: str, payload: dict[str, Any]) -> str:
    """Hash one entry together with the hash of the entry before it.

    sort_keys matters. Two dicts with the same contents in a different order
    must produce the same hash, otherwise verification would fail at random.
    """
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((previous_hash + body).encode()).hexdigest()


@dataclass
class AuditLog:
    """Writes entries to a JSONL file, one JSON object per line."""

    path: Path = DEFAULT_PATH

    def append(self, **fields: Any) -> str:
        """Add an entry and return its hash."""
        payload = {"ts": datetime.now(UTC).isoformat(), **fields}
        previous = self._last_hash()
        digest = _fingerprint(previous, payload)

        line = json.dumps({**payload, "prev": previous, "hash": digest})
        with self.path.open("a") as handle:
            handle.write(line + "\n")
        return digest

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open() as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def _last_hash(self) -> str:
        entries = self.entries()
        return entries[-1]["hash"] if entries else GENESIS


def verify(path: Path = DEFAULT_PATH) -> tuple[bool, str]:
    """Walk the chain and check every link.

    Returns (True, message) if the file is intact, (False, reason) if someone
    edited, reordered, or removed a line.
    """
    log = AuditLog(path)
    entries = log.entries()
    if not entries:
        return True, "log is empty"

    previous = GENESIS
    for number, entry in enumerate(entries, start=1):
        stored_hash = entry.get("hash")
        stored_prev = entry.get("prev")

        if stored_prev != previous:
            return False, f"line {number}: expected to follow {previous[:12]}, found {stored_prev}"

        payload = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
        if _fingerprint(previous, payload) != stored_hash:
            return False, f"line {number}: contents do not match the hash, it was edited"

        previous = str(stored_hash)

    return True, f"{len(entries)} entries, chain intact"


def main() -> None:
    """Check a log file from the command line."""
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    ok, message = verify(target)
    print(("OK   " if ok else "BROKEN ") + message)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
