"""The audit log is only useful if tampering actually breaks it, so test that."""

import json
from pathlib import Path

from gateway.audit import AuditLog, verify


def test_empty_log_is_valid(tmp_path: Path) -> None:
    ok, _ = verify(tmp_path / "audit.jsonl")
    assert ok


def test_entries_chain_together(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(tool="read_document", decision="allow")
    log.append(tool="http_post", decision="deny")

    entries = log.entries()
    assert entries[1]["prev"] == entries[0]["hash"]

    ok, message = verify(log.path)
    assert ok, message


def test_editing_an_entry_is_detected(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(tool="http_post", decision="deny")
    log.append(tool="read_document", decision="allow")

    # Flip a denial into an approval, the way someone covering their tracks would.
    lines = log.path.read_text().splitlines()
    first = json.loads(lines[0])
    first["decision"] = "allow"
    lines[0] = json.dumps(first)
    log.path.write_text("\n".join(lines) + "\n")

    ok, message = verify(log.path)
    assert not ok
    assert "edited" in message


def test_deleting_an_entry_is_detected(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(tool="a")
    log.append(tool="b")
    log.append(tool="c")

    lines = log.path.read_text().splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n")

    ok, message = verify(log.path)
    assert not ok
    assert "expected to follow" in message
