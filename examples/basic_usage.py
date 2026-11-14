"""Minimal end-to-end demo: add, read, tamper, detect.

Run with ``python examples/basic_usage.py`` after ``pip install -e .``.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from memtrace import AuditMemoryAdapter


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
        print("read after tampering: ", [r.content for r in adapter.get_memory("refund")])

        for event in adapter.list_audit_events("READ_EXCLUDED"):
            print("audit:", event.event_type, event.details["status"], event.memory_id == policy.memory_id)


if __name__ == "__main__":
    main()