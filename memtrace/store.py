"""A mock SQLite-backed memory store with deterministic lexical search.

``SimpleLexicalStore`` stands in for the memory store an agent already uses.  It
does substring matching only: there are no embeddings and no vector search.  It
is intentionally tiny: the audit layer must work with *any* store that
implements the :class:`MemoryStore` protocol.  A real vector store would replace
``search`` without touching the adapter.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Protocol

from memtrace.models import content_hash, escape_like


@dataclass(frozen=True, slots=True)
class StoredItem:
    """What a store currently holds for one memory id."""

    memory_id: str
    content: str


class MemoryStore(Protocol):
    """Minimal contract an existing memory store must satisfy.

    Every method receives the caller's transaction connection.  A store that
    lives in the same SQLite database as the ledger therefore commits or rolls
    back together with it.  A store that lives elsewhere ignores ``conn`` and
    needs its own compensation logic (out of scope for Day 1).
    """

    def schema_statements(self) -> tuple[str, ...]:
        """Return idempotent DDL statements for a store sharing the database."""
        ...

    def put(self, conn: sqlite3.Connection, memory_id: str, content: str) -> None:
        """Insert or replace the content stored for ``memory_id``."""
        ...

    def get(self, conn: sqlite3.Connection, memory_id: str) -> StoredItem | None:
        """Return the stored item, or ``None`` when it does not exist."""
        ...

    def search(self, conn: sqlite3.Connection, query: str) -> list[str]:
        """Return ids of stored items matching ``query``, in a stable order."""
        ...


class SimpleLexicalStore:
    """SQLite table with deterministic substring search (SQL ``LIKE``).

    ``content_hash`` is kept the way real stores keep denormalised columns, but
    the integrity monitor deliberately never trusts it: anyone able to edit
    ``content`` can edit this column too.
    """

    TABLE = "store_items"

    def schema_statements(self) -> tuple[str, ...]:
        """Return the DDL for the store table."""
        return (
            f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                memory_id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL
            )
            """,
        )

    def put(self, conn: sqlite3.Connection, memory_id: str, content: str) -> None:
        """Insert or replace ``content`` (keeps the row position on replace)."""
        conn.execute(
            f"""
            INSERT INTO {self.TABLE} (memory_id, content, content_hash)
            VALUES (?, ?, ?)
            ON CONFLICT (memory_id) DO UPDATE SET
                content = excluded.content,
                content_hash = excluded.content_hash
            """,
            (memory_id, content, content_hash(content)),
        )

    def get(self, conn: sqlite3.Connection, memory_id: str) -> StoredItem | None:
        """Return the item for ``memory_id`` or ``None``."""
        row = conn.execute(
            f"SELECT memory_id, content FROM {self.TABLE} WHERE memory_id = ?",
            (memory_id,),
        ).fetchone()
        if row is None:
            return None
        return StoredItem(memory_id=str(row["memory_id"]), content=str(row["content"]))

    def search(self, conn: sqlite3.Connection, query: str) -> list[str]:
        """Return ids whose content contains ``query`` (ASCII case-insensitive)."""
        rows = conn.execute(
            f"""
            SELECT memory_id FROM {self.TABLE}
            WHERE content LIKE ? ESCAPE '\\'
            ORDER BY rowid
            """,
            (f"%{escape_like(query)}%",),
        ).fetchall()
        return [str(row["memory_id"]) for row in rows]