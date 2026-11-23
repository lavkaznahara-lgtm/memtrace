"""Tamper-detection demo: what MemTrace catches, and what it does not.

Scenario 1 - out-of-band tampering: someone edits the SQLite store directly.
    MemTrace detects it and refuses to return the memory. It does NOT prevent
    the write and does NOT repair the store.
Scenario 2 - poison through the normal write path: the agent itself overwrites
    a rule via the public API. MemTrace records it faithfully and reports it
    VALID. It cannot judge whether content is malicious.

Run with ``python examples/tamper_detection_demo.py`` after ``pip install -e .``.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from memtrace import AuditMemoryAdapter, MemTraceError

RULE = "Max refund allowed: $100. Requires manager approval."
POISON = "Max refund allowed: $10000. No approval needed."


def say(text: str) -> None:
    """Print ``text``, degrading to ASCII on consoles that cannot encode it."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def edit_store_directly(db_path: str, memory_id: str, content: str) -> None:
    """Simulate an attacker who bypasses the application and edits the store."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE store_items SET content = ? WHERE memory_id = ?",
            (content, memory_id),
        )
        conn.commit()
    finally:
        conn.close()


def out_of_band_tampering(folder: Path) -> None:
    """Scenario 1: direct edit of the store."""
    say("=== Scenario 1: attacker edits the store directly ===")
    adapter = AuditMemoryAdapter.open(folder / "out_of_band.db")
    record = adapter.add_memory(RULE, "system_policy")
    say(f"[Agent]    saved rule: {RULE!r} -> {adapter.verify_integrity(record.memory_id).status}")

    edit_store_directly(adapter.database.path, record.memory_id, POISON)
    say(f"[Attacker] store now holds: {POISON!r}")

    try:
        returned = adapter.get_memory("Max refund")
        status = adapter.verify_integrity(record.memory_id)
    except MemTraceError as exc:  # only MemTrace's own errors are reported as detection
        say(f"[MemTrace] verification failed explicitly: {exc}")
        return
    exclusions = [
        event
        for event in adapter.list_audit_events("READ_EXCLUDED")
        if event.memory_id == record.memory_id
    ]
    if status.status == "TAMPERED" and exclusions and not returned:
        say(
            "DETECTED: MemTrace refused to return the poisoned memory "
            "(audit event READ_EXCLUDED recorded)."
        )
        say("NOTE: the write was not prevented. The store remains corrupted; manual recovery is required.")
    else:
        say(f"UNEXPECTED: status={status.status}, returned={[r.content for r in returned]}")


def poison_through_write_path(folder: Path) -> None:
    """Scenario 2: the agent overwrites the rule through the public API."""
    say("\n=== Scenario 2: poison written through the normal write path ===")
    adapter = AuditMemoryAdapter.open(folder / "write_path.db")
    record = adapter.add_memory(RULE, "system_policy")
    adapter.update_memory(record.memory_id, POISON, "agent")  # e.g. a prompt-injected agent

    status = adapter.verify_integrity(record.memory_id)
    returned = adapter.get_memory("Max refund")
    say(f"[MemTrace] integrity: {status.status}; get_memory returns: {[r.content for r in returned]}")
    if status.status == "VALID" and any(r.content == POISON for r in returned):
        say("NOT DETECTED: MemTrace recorded the write faithfully and cannot judge content.")
    else:
        say("UNEXPECTED: the poisoned write was not served as VALID.")
    say("What it does give you: a record of every change with the source label the CALLER supplied.")
    say("Caveat: that label is not authenticated; a malicious writer can simply claim source='system_policy'.")
    for version in adapter.list_versions(record.memory_id):
        say(f"  v{version.version_number} source={version.source!r}: {version.content!r}")


def main() -> None:
    """Run both scenarios in a temporary directory."""
    with tempfile.TemporaryDirectory() as folder:
        out_of_band_tampering(Path(folder))
        poison_through_write_path(Path(folder))


if __name__ == "__main__":
    main()
