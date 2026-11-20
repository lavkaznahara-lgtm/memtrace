"""Provenance ledger: SQLite connection management, schema and typed access.

The ledger keeps four tables:

``memories``
    one row per logical memory; ``current_version_id`` points at its latest
    version.
``memory_versions``
    immutable version history (content, hash, source, parent ids).
``audit_events``
    append-only log of writes, reads, exclusions and refusals.
``memory_reads``
    append-only record of exactly which memory versions each read returned.

Security boundary: the triggers below make accidental or naive modification
fail, but anyone with write access to the SQLite file can drop them.  They are
not a cryptographic protection (see README).
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from typing import Final

from memtrace.models import (
    AuditEvent,
    IntegrityError,
    MemoryNotFoundError,
    MemoryRecord,
    StorageError,
    content_hash,
    escape_like,
)

SCHEMA_VERSION: Final = 1

EVENT_MEMORY_ADDED: Final = "MEMORY_ADDED"
EVENT_MEMORY_UPDATED: Final = "MEMORY_UPDATED"
EVENT_READ: Final = "READ"
EVENT_READ_EXCLUDED: Final = "READ_EXCLUDED"
EVENT_INTEGRITY_FAILED: Final = "INTEGRITY_FAILED"
EVENT_UPDATE_REFUSED: Final = "UPDATE_REFUSED"

EVENT_TYPES: Final[tuple[str, ...]] = (
    EVENT_MEMORY_ADDED,
    EVENT_MEMORY_UPDATED,
    EVENT_READ,
    EVENT_READ_EXCLUDED,
    EVENT_INTEGRITY_FAILED,
    EVENT_UPDATE_REFUSED,
)
_EVENT_TYPE_SQL: Final = ", ".join(f"'{name}'" for name in EVENT_TYPES)

# One statement per tuple item: trigger bodies contain ';', so a script cannot
# be split safely, and executing statements one by one lets the whole schema be
# created inside a single transaction.
LEDGER_SCHEMA: Final[tuple[str, ...]] = (
    """
    CREATE TABLE IF NOT EXISTS memories (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id TEXT NOT NULL UNIQUE,
        current_version_id TEXT REFERENCES memory_versions (version_id),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS memory_versions (
        version_id TEXT PRIMARY KEY,
        memory_id TEXT NOT NULL REFERENCES memories (memory_id),
        version_number INTEGER NOT NULL CHECK (version_number >= 1),
        content TEXT NOT NULL,
        content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
        source TEXT NOT NULL,
        parent_ids TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (memory_id, version_number)
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL CHECK (event_type IN ({_EVENT_TYPE_SQL})),
        memory_id TEXT REFERENCES memories (memory_id),
        version_id TEXT REFERENCES memory_versions (version_id),
        read_id TEXT,
        details TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS memory_reads (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        read_id TEXT NOT NULL,
        query TEXT NOT NULL,
        position INTEGER NOT NULL CHECK (position >= 0),
        memory_id TEXT NOT NULL REFERENCES memories (memory_id),
        version_id TEXT NOT NULL REFERENCES memory_versions (version_id),
        created_at TEXT NOT NULL,
        UNIQUE (read_id, position)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_memories_current_version "
    "ON memories (current_version_id)",
    "CREATE INDEX IF NOT EXISTS idx_versions_memory "
    "ON memory_versions (memory_id, version_number)",
    "CREATE INDEX IF NOT EXISTS idx_events_memory ON audit_events (memory_id, seq)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON audit_events (event_type, seq)",
    "CREATE INDEX IF NOT EXISTS idx_events_read ON audit_events (read_id)",
    "CREATE INDEX IF NOT EXISTS idx_reads_read ON memory_reads (read_id, position)",
    "CREATE INDEX IF NOT EXISTS idx_reads_memory ON memory_reads (memory_id, seq)",
    """
    CREATE TRIGGER IF NOT EXISTS memory_versions_no_update
    BEFORE UPDATE ON memory_versions
    BEGIN SELECT RAISE(ABORT, 'memory_versions is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS memory_versions_no_delete
    BEFORE DELETE ON memory_versions
    BEGIN SELECT RAISE(ABORT, 'memory_versions is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_events_no_update
    BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
    BEFORE DELETE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS memory_reads_no_update
    BEFORE UPDATE ON memory_reads
    BEGIN SELECT RAISE(ABORT, 'memory_reads is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS memory_reads_no_delete
    BEFORE DELETE ON memory_reads
    BEGIN SELECT RAISE(ABORT, 'memory_reads is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS memories_no_delete
    BEFORE DELETE ON memories
    BEGIN SELECT RAISE(ABORT, 'memories rows cannot be deleted'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS memories_id_immutable
    BEFORE UPDATE OF memory_id ON memories
    BEGIN SELECT RAISE(ABORT, 'memory_id is immutable'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS memories_pointer_valid
    BEFORE UPDATE OF current_version_id ON memories
    WHEN NEW.current_version_id IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'current_version_id must belong to the same memory')
        WHERE (SELECT memory_id FROM memory_versions
               WHERE version_id = NEW.current_version_id) IS NOT NEW.memory_id;
    END
    """,
)


class Database:
    """A file-backed SQLite database with explicit connection management.

    Every :meth:`transaction` opens its own connection, enables foreign keys on
    it, runs ``BEGIN IMMEDIATE`` (so writers are serialised and version numbers
    cannot race), commits on success, rolls back on failure and *always* closes
    the connection.  WAL mode is switched on exactly once, while initialising.

    In-memory databases are rejected: each connection would see a different,
    empty database, which silently breaks transactional consistency.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        schema: Sequence[str] = (),
        *,
        timeout_s: float = 5.0,
    ) -> None:
        """Open (and if needed initialise) the database at ``path``.

        ``schema`` is a sequence of idempotent DDL statements applied once, in a
        single transaction, after the ledger's own schema.
        """
        self._path = os.fspath(path)
        self._timeout_s = timeout_s
        if self._path in ("", ":memory:") or self._path.startswith("file::memory:"):
            raise ValueError("a file-backed database path is required")
        self._initialize(tuple(schema))

    @property
    def path(self) -> str:
        """Return the database file path."""
        return self._path

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with foreign keys enforced (verified)."""
        try:
            conn = sqlite3.connect(
                self._path, timeout=self._timeout_s, isolation_level=None
            )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {self._path!r}: {exc}") from exc
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            row = conn.execute("PRAGMA foreign_keys").fetchone()
            if row is None or int(row[0]) != 1:
                raise StorageError("SQLite foreign key enforcement is unavailable")
        except sqlite3.Error as exc:
            conn.close()
            raise StorageError(f"cannot configure connection: {exc}") from exc
        except BaseException:
            conn.close()
            raise
        return conn

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        """Roll back an open transaction; never raise (the connection closes next)."""
        if conn.in_transaction:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

    def _initialize(self, extra_schema: tuple[str, ...]) -> None:
        """Enable WAL once and create the schema atomically."""
        conn = self._connect()
        try:
            mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise StorageError("could not enable WAL journal mode")
            conn.execute("BEGIN IMMEDIATE")
            version_row = conn.execute("PRAGMA user_version").fetchone()
            version = 0 if version_row is None else int(version_row[0])
            if version not in (0, SCHEMA_VERSION):
                raise StorageError(
                    f"unsupported ledger schema version {version} "
                    f"(expected {SCHEMA_VERSION})"
                )
            for statement in (*LEDGER_SCHEMA, *extra_schema):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self._rollback(conn)
            raise StorageError(f"cannot initialise database: {exc}") from exc
        except BaseException:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection inside a transaction; commit, roll back, close.

        ``sqlite3.Error`` raised in the block (or at commit) is re-raised as
        :class:`StorageError`; any other exception propagates unchanged after
        the rollback.
        """
        conn = self._connect()
        try:
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
            except BaseException as exc:
                self._rollback(conn)
                if isinstance(exc, sqlite3.Error):
                    raise StorageError(f"database error: {exc}") from exc
                raise
            else:
                try:
                    conn.execute("COMMIT")
                except sqlite3.Error as exc:
                    self._rollback(conn)
                    raise StorageError(f"commit failed: {exc}") from exc
        finally:
            conn.close()


def _text(row: sqlite3.Row, key: str) -> str:
    """Return a TEXT column, failing closed if the ledger holds something else."""
    value = row[key]
    if not isinstance(value, str):
        raise IntegrityError(f"ledger column {key!r} is not text")
    return value


def _integer(row: sqlite3.Row, key: str) -> int:
    """Return an INTEGER column, failing closed on anything else."""
    value = row[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise IntegrityError(f"ledger column {key!r} is not an integer")
    return value


def _timestamp(row: sqlite3.Row, key: str) -> datetime:
    """Parse an ISO-8601 TEXT column."""
    try:
        return datetime.fromisoformat(_text(row, key))
    except ValueError as exc:
        raise IntegrityError(f"ledger column {key!r} is not a timestamp") from exc


def _parent_ids(row: sqlite3.Row) -> tuple[str, ...]:
    """Decode the ordered JSON list of parent ids."""
    try:
        decoded = json.loads(_text(row, "parent_ids"))
    except json.JSONDecodeError as exc:
        raise IntegrityError("ledger parent_ids is not valid JSON") from exc
    if not isinstance(decoded, list) or not all(isinstance(i, str) for i in decoded):
        raise IntegrityError("ledger parent_ids is not a list of strings")
    return tuple(decoded)


def _record(row: sqlite3.Row) -> MemoryRecord:
    """Convert a ``memory_versions`` row to a :class:`MemoryRecord`."""
    return MemoryRecord(
        memory_id=_text(row, "memory_id"),
        version_id=_text(row, "version_id"),
        version_number=_integer(row, "version_number"),
        content=_text(row, "content"),
        source=_text(row, "source"),
        parent_ids=_parent_ids(row),
        created_at=_timestamp(row, "created_at"),
        content_hash=_text(row, "content_hash"),
    )


_VERSION_COLUMNS: Final = (
    "version_id, memory_id, version_number, content, content_hash, "
    "source, parent_ids, created_at"
)


class Ledger:
    """Typed access to the provenance tables.

    Stateless: every method takes the caller's transaction connection, so a
    ledger write and a store write can commit or roll back together.
    """

    def create_memory(
        self, conn: sqlite3.Connection, memory_id: str, created_at: datetime
    ) -> None:
        """Insert a logical memory with no current version yet."""
        conn.execute(
            "INSERT INTO memories (memory_id, current_version_id, created_at) "
            "VALUES (?, NULL, ?)",
            (memory_id, created_at.isoformat()),
        )

    def memory_exists(self, conn: sqlite3.Connection, memory_id: str) -> bool:
        """Return whether ``memory_id`` is a tracked logical memory."""
        row = conn.execute(
            "SELECT 1 FROM memories WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        return row is not None

    def append_version(
        self,
        conn: sqlite3.Connection,
        *,
        memory_id: str,
        version_id: str,
        version_number: int,
        content: str,
        content_hash: str,
        source: str,
        parent_ids: tuple[str, ...],
        created_at: datetime,
    ) -> MemoryRecord:
        """Append an immutable version and return it as a record."""
        conn.execute(
            f"INSERT INTO memory_versions ({_VERSION_COLUMNS}) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                version_id,
                memory_id,
                version_number,
                content,
                content_hash,
                source,
                json.dumps(list(parent_ids)),
                created_at.isoformat(),
            ),
        )
        return MemoryRecord(
            memory_id=memory_id,
            version_id=version_id,
            version_number=version_number,
            content=content,
            source=source,
            parent_ids=parent_ids,
            created_at=created_at,
            content_hash=content_hash,
        )

    def set_current_version(
        self, conn: sqlite3.Connection, memory_id: str, version_id: str
    ) -> None:
        """Point the logical memory at ``version_id`` (validated by a trigger)."""
        conn.execute(
            "UPDATE memories SET current_version_id = ? WHERE memory_id = ?",
            (version_id, memory_id),
        )

    def get_current_version(
        self, conn: sqlite3.Connection, memory_id: str
    ) -> MemoryRecord:
        """Return the version the logical memory currently references.

        Raises :class:`MemoryNotFoundError` for an unknown memory and
        :class:`IntegrityError` if the ledger itself is inconsistent, including
        a version whose content no longer matches its recorded hash.  That
        self-check does not depend on any SQLite trigger.
        """
        head = conn.execute(
            "SELECT current_version_id FROM memories WHERE memory_id = ?",
            (memory_id,),
        ).fetchone()
        if head is None:
            raise MemoryNotFoundError(f"unknown memory_id {memory_id!r}")
        version_id = head["current_version_id"]
        if version_id is None:
            raise IntegrityError(f"memory {memory_id!r} has no current version")
        row = conn.execute(
            f"SELECT {_VERSION_COLUMNS} FROM memory_versions WHERE version_id = ?",
            (version_id,),
        ).fetchone()
        if row is None or row["memory_id"] != memory_id:
            raise IntegrityError(
                f"memory {memory_id!r} references a missing or foreign version"
            )
        record = _record(row)
        if content_hash(record.content) != record.content_hash:
            raise IntegrityError(
                f"ledger version {record.version_id!r} is internally "
                "inconsistent: its content does not match its recorded hash"
            )
        return record

    def list_versions(
        self, conn: sqlite3.Connection, memory_id: str
    ) -> list[MemoryRecord]:
        """Return every version of ``memory_id``, oldest first."""
        if not self.memory_exists(conn, memory_id):
            raise MemoryNotFoundError(f"unknown memory_id {memory_id!r}")
        rows = conn.execute(
            f"SELECT {_VERSION_COLUMNS} FROM memory_versions "
            "WHERE memory_id = ? ORDER BY version_number",
            (memory_id,),
        ).fetchall()
        return [_record(row) for row in rows]

    def search_current(self, conn: sqlite3.Connection, query: str) -> list[str]:
        """Return ids whose *current ledger version* contains ``query``.

        Same literal, ASCII case-insensitive rule as the store, in creation
        order.  This shadow search is what lets a read notice memories whose
        stored copy was deleted or rewritten.
        """
        rows = conn.execute(
            """
            SELECT m.memory_id FROM memories AS m
            JOIN memory_versions AS v ON v.version_id = m.current_version_id
            WHERE v.content LIKE ? ESCAPE '\\'
            ORDER BY m.seq
            """,
            (f"%{escape_like(query)}%",),
        ).fetchall()
        return [str(row["memory_id"]) for row in rows]

    def order_tracked(
        self, conn: sqlite3.Connection, memory_ids: Sequence[str]
    ) -> list[str]:
        """Return the tracked subset of ``memory_ids`` in creation order."""
        tracked: list[tuple[int, str]] = []
        chunk = 500
        for start in range(0, len(memory_ids), chunk):
            part = memory_ids[start : start + chunk]
            marks = ", ".join("?" for _ in part)
            rows = conn.execute(
                f"SELECT seq, memory_id FROM memories WHERE memory_id IN ({marks})",
                tuple(part),
            ).fetchall()
            tracked.extend((int(r["seq"]), str(r["memory_id"])) for r in rows)
        return [memory_id for _, memory_id in sorted(tracked)]

    def record_event(
        self,
        conn: sqlite3.Connection,
        *,
        event_id: str,
        event_type: str,
        created_at: datetime,
        memory_id: str | None = None,
        version_id: str | None = None,
        read_id: str | None = None,
        details: Mapping[str, object] | None = None,
    ) -> None:
        """Append an audit event (never contains stored content)."""
        conn.execute(
            "INSERT INTO audit_events "
            "(event_id, event_type, memory_id, version_id, read_id, details, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                event_type,
                memory_id,
                version_id,
                read_id,
                json.dumps(dict(details or {}), sort_keys=True),
                created_at.isoformat(),
            ),
        )

    def record_read(
        self,
        conn: sqlite3.Connection,
        *,
        read_id: str,
        query: str,
        position: int,
        memory_id: str,
        version_id: str,
        created_at: datetime,
    ) -> None:
        """Append one returned memory version of a read."""
        conn.execute(
            "INSERT INTO memory_reads "
            "(read_id, query, position, memory_id, version_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (read_id, query, position, memory_id, version_id, created_at.isoformat()),
        )

    def list_events(
        self, conn: sqlite3.Connection, event_type: str | None = None
    ) -> list[AuditEvent]:
        """Return audit events in insertion order, optionally of one type."""
        if event_type is None:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE event_type = ? ORDER BY seq",
                (event_type,),
            ).fetchall()
        return [_event(row) for row in rows]


def _optional_text(row: sqlite3.Row, key: str) -> str | None:
    """Return a nullable TEXT column."""
    return None if row[key] is None else _text(row, key)


def _event(row: sqlite3.Row) -> AuditEvent:
    """Convert an ``audit_events`` row to an :class:`AuditEvent`."""
    try:
        decoded = json.loads(_text(row, "details"))
    except json.JSONDecodeError as exc:
        raise IntegrityError("audit event details are not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise IntegrityError("audit event details are not an object")
    return AuditEvent(
        seq=_integer(row, "seq"),
        event_id=_text(row, "event_id"),
        event_type=_text(row, "event_type"),
        memory_id=_optional_text(row, "memory_id"),
        version_id=_optional_text(row, "version_id"),
        read_id=_optional_text(row, "read_id"),
        details=decoded,
        created_at=_timestamp(row, "created_at"),
    )