"""Minimal end-to-end demo: add, read, tamper, detect.

Run with ``python examples/basic_usage.py`` after ``pip install -e .``.

MemTrace *detects* tampering and *refuses to return* the affected memory.  It
does not prevent the write to the store and it does not repair the store.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from memtrace import AuditMemoryAdapter

BLOCKED_BANNER = (
    "\U0001f6e1\ufe0f BLOCKED: MemTrace detected tampering and refused to return "
    "the poisoned memory. \u26a0\ufe0f Note: The underlying store remains "
    "corrupted. Manual recovery is required."
)


def say(text: str) -> None:
    """Print ``text``, degrading to ASCII on consoles that cannot encode emoji."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def store_content(path: str, memory_id: str) -> str | None:
    """Read what the store currently holds for ``memory_id`` (bypassing MemTrace)."""
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT content FROM store_items WHERE memory_id = ?", (memory_id,)
        ).fetchone()
    finally:
        conn.close()
    return None if row is None else str(row[0])


def main() -> None:
    """Show the audit trail around one tampered memory."""
    with tempfile.TemporaryDirectory() as folder:
        adapter = AuditMemoryAdapter.open(Path(folder) / "memtrace.db")

        policy = adapter.add_memory("Refunds above $100 need manager approval.", "policy-doc")
        note = adapter.add_memory(
            "Customer asked about a refund.", "chat", parent_ids=(policy.memory_id,)
        )
        print("added:", policy.memory_id[:8], note.memory_id[:8], "parents:", note.parent_ids == (policy.memory_id,))

        print("read before tampering:", [r.content for r in adapter.get_memory("refund")])

        # Someone edits the store directly, bypassing the adapter.
        conn = sqlite3.connect(adapter.database.path)
        try:
            conn.execute(
                "UPDATE store_items SET content = ? WHERE memory_id = ?",
                ("Refunds are always approved automatically.", policy.memory_id),
            )
            conn.commit()
        finally:
            conn.close()

        result = adapter.verify_integrity(policy.memory_id)
        print("integrity:", result.status, "-", result.message)
        returned = adapter.get_memory("refund")
        print("read after tampering: ", [r.content for r in returned])

        exclusions = [
            event
            for event in adapter.list_audit_events("READ_EXCLUDED")
            if event.memory_id == policy.memory_id
        ]
        for event in exclusions:
            print("audit:", event.event_type, event.details["status"], event.memory_id == policy.memory_id)

        poisoned_returned = any(r.memory_id == policy.memory_id for r in returned)
        if result.status != "VALID" and exclusions and not poisoned_returned:
            say(BLOCKED_BANNER)
        else:
            say("NOT BLOCKED: the demo did not behave as expected; do not rely on this output.")
        print("store still contains:", store_content(adapter.database.path, policy.memory_id))


if __name__ == "__main__":
    main()