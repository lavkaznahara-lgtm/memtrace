"""Tests for AuditMemoryAdapter behaviour and SQLite connection management."""

from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from memtrace import (
    AuditMemoryAdapter,
    Database,
    IntegrityError,
    MemoryNotFoundError,
    SimpleVectorStore,
    StorageError,
)


def make_id_factory() -> Callable[[], str]:
    """Return a deterministic id generator (no global state)."""
    counter = itertools.count(1)
    return lambda: f"id-{next(counter):04d}"


def make_clock() -> Callable[[], datetime]:
    """Return a deterministic clock that advances one second per call."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ticks = itertools.count()
    return lambda: start + timedelta(seconds=next(ticks))


@pytest.fixture()
def adapter(tmp_path: Path) -> AuditMemoryAdapter:
    """An adapter over a fresh file database with deterministic ids and time."""
    return AuditMemoryAdapter.open(
        tmp_path / "memtrace.db", clock=make_clock(), id_factory=make_id_factory()
    )


def execute_sql(path: str, sql: str, params: tuple[object, ...] = ()) -> None:
    """Run one statement on a plain connection (simulates an outside actor)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def query_sql(
    path: str, sql: str, params: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    """Run one query on a plain connection and return all rows."""
    conn = sqlite3.connect(path)
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def count_rows(path: str, table: str) -> int:
    """Return the number of rows in ``table``."""
    value = query_sql(path, f"SELECT COUNT(*) FROM {table}")[0][0]
    assert isinstance(value, int)
    return value


# --------------------------------------------------------------------------- #
# add / get
# --------------------------------------------------------------------------- #


def test_add_and_retrieve_memory(adapter: AuditMemoryAdapter) -> None:
    added = adapter.add_memory("The customer prefers email contact.", "user")

    found = adapter.get_memory("prefers email")

    assert found == [added]
    assert added.version_number == 1
    assert added.parent_ids == ()
    assert added.source == "user"


def test_content_hash_matches_sha256_and_the_ledger(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("hello world", "user")
    expected = hashlib.sha256(b"hello world").hexdigest()

    ledger_rows = query_sql(
        adapter.database.path,
        "SELECT content_hash FROM memory_versions WHERE version_id = ?",
        (record.version_id,),
    )
    result = adapter.verify_integrity(record.memory_id)

    assert record.content_hash == expected
    assert ledger_rows == [(expected,)]
    assert result.status == "VALID"
    assert result.expected_hash == result.actual_hash == expected


def test_multiple_parent_ids_are_preserved_in_order(
    adapter: AuditMemoryAdapter,
) -> None:
    first = adapter.add_memory("alpha fact", "user")
    second = adapter.add_memory("bravo fact", "user")
    third = adapter.add_memory("charlie fact", "user")
    parents = (third.memory_id, first.memory_id, second.memory_id)

    child = adapter.add_memory("delta summary", "agent", parent_ids=parents)

    stored = query_sql(
        adapter.database.path,
        "SELECT parent_ids FROM memory_versions WHERE version_id = ?",
        (child.version_id,),
    )
    assert child.parent_ids == parents
    assert adapter.get_memory("delta summary")[0].parent_ids == parents
    assert json.loads(str(stored[0][0])) == list(parents)


def test_unknown_parent_is_rejected_and_nothing_is_written(
    adapter: AuditMemoryAdapter,
) -> None:
    with pytest.raises(MemoryNotFoundError):
        adapter.add_memory("orphan", "agent", parent_ids=("does-not-exist",))

    for table in ("memories", "memory_versions", "audit_events", "store_items"):
        assert count_rows(adapter.database.path, table) == 0


@pytest.mark.parametrize(
    ("content", "source"),
    [("", "user"), ("   ", "user"), ("fact", ""), ("fact", "  "), ("bad \ud800", "user")],
)
def test_add_memory_rejects_invalid_arguments(
    adapter: AuditMemoryAdapter, content: str, source: str
) -> None:
    with pytest.raises(ValueError):
        adapter.add_memory(content, source)
    assert count_rows(adapter.database.path, "memories") == 0


def test_duplicate_parent_ids_are_rejected(adapter: AuditMemoryAdapter) -> None:
    parent = adapter.add_memory("parent fact", "user")
    with pytest.raises(ValueError, match="duplicates"):
        adapter.add_memory("child", "agent", parent_ids=(parent.memory_id, parent.memory_id))


def test_blank_query_is_rejected(adapter: AuditMemoryAdapter) -> None:
    with pytest.raises(ValueError):
        adapter.get_memory("   ")


def test_query_is_matched_literally(adapter: AuditMemoryAdapter) -> None:
    adapter.add_memory("discount is 50% today", "user")
    adapter.add_memory("discount is 500 today", "user")

    found = adapter.get_memory("50%")

    assert [r.content for r in found] == ["discount is 50% today"]


# --------------------------------------------------------------------------- #
# read events
# --------------------------------------------------------------------------- #


def test_read_events_record_the_exact_returned_memory_ids(
    adapter: AuditMemoryAdapter,
) -> None:
    first = adapter.add_memory("alpha release notes", "user")
    adapter.add_memory("bravo release notes", "user")
    third = adapter.add_memory("alpha rollout plan", "user")

    found = adapter.get_memory("alpha")

    assert [r.memory_id for r in found] == [first.memory_id, third.memory_id]
    rows = query_sql(
        adapter.database.path,
        "SELECT read_id, query, position, memory_id, version_id "
        "FROM memory_reads ORDER BY seq",
    )
    assert [row[1:] for row in rows] == [
        ("alpha", 0, first.memory_id, first.version_id),
        ("alpha", 1, third.memory_id, third.version_id),
    ]
    assert len({row[0] for row in rows}) == 1
    events = adapter.list_audit_events("READ")
    assert len(events) == 1
    assert events[0].read_id == rows[0][0]
    assert events[0].details["query"] == "alpha"
    assert events[0].details["returned_memory_ids"] == [
        first.memory_id,
        third.memory_id,
    ]
    assert events[0].details["returned_version_ids"] == [
        first.version_id,
        third.version_id,
    ]


def test_empty_search_returns_empty_list_and_is_still_recorded(
    adapter: AuditMemoryAdapter,
) -> None:
    adapter.add_memory("something unrelated", "user")

    assert adapter.get_memory("no such text") == []

    events = adapter.list_audit_events("READ")
    assert len(events) == 1
    assert events[0].details["returned_memory_ids"] == []
    assert count_rows(adapter.database.path, "memory_reads") == 0


# --------------------------------------------------------------------------- #
# update
# --------------------------------------------------------------------------- #


def test_update_keeps_identity_and_increments_the_version(
    adapter: AuditMemoryAdapter,
) -> None:
    parent = adapter.add_memory("parent fact", "user")
    other = adapter.add_memory("second parent", "user")
    parents = (other.memory_id, parent.memory_id)
    first = adapter.add_memory("draft summary", "agent", parent_ids=parents)
    before = query_sql(
        adapter.database.path,
        "SELECT * FROM memory_versions WHERE memory_id = ?",
        (first.memory_id,),
    )

    second = adapter.update_memory(first.memory_id, "final summary", "reviewer")
    third = adapter.update_memory(first.memory_id, "final summary v3", "reviewer")

    assert second.memory_id == first.memory_id == third.memory_id
    assert len({first.version_id, second.version_id, third.version_id}) == 3
    assert (first.version_number, second.version_number, third.version_number) == (
        1,
        2,
        3,
    )
    assert second.parent_ids == third.parent_ids == first.parent_ids == parents
    assert second.source == "reviewer"
    assert second.content == "final summary"
    after = query_sql(
        adapter.database.path,
        "SELECT * FROM memory_versions WHERE memory_id = ? ORDER BY version_number",
        (first.memory_id,),
    )
    assert len(after) == 3
    assert after[:1] == before  # the previous version row is untouched


def test_get_memory_returns_only_the_latest_version(
    adapter: AuditMemoryAdapter,
) -> None:
    first = adapter.add_memory("pricing: 10 dollars", "user")
    adapter.update_memory(first.memory_id, "pricing: 12 dollars", "user")

    assert adapter.get_memory("10 dollars") == []
    found = adapter.get_memory("pricing")
    assert len(found) == 1
    assert found[0].version_number == 2
    assert found[0].content == "pricing: 12 dollars"


def test_update_does_not_modify_or_delete_previous_versions(
    adapter: AuditMemoryAdapter,
) -> None:
    first = adapter.add_memory("original text", "user")
    snapshot = query_sql(adapter.database.path, "SELECT * FROM memory_versions")

    adapter.update_memory(first.memory_id, "changed text", "user")

    rows = query_sql(
        adapter.database.path, "SELECT * FROM memory_versions ORDER BY version_number"
    )
    assert rows[: len(snapshot)] == snapshot
    assert len(rows) == len(snapshot) + 1
    assert [v.content for v in adapter.list_versions(first.memory_id)] == [
        "original text",
        "changed text",
    ]


@pytest.mark.parametrize("table", ["memory_versions", "audit_events", "memory_reads"])
def test_history_tables_reject_update_and_delete(
    adapter: AuditMemoryAdapter, table: str
) -> None:
    adapter.add_memory("history fact", "user")
    adapter.get_memory("history")  # creates a memory_reads row
    conn = sqlite3.connect(adapter.database.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(f"UPDATE {table} SET created_at = 'x'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(f"DELETE FROM {table}")
    finally:
        conn.close()
    assert count_rows(adapter.database.path, table) >= 1


def test_update_of_an_unknown_memory_raises(adapter: AuditMemoryAdapter) -> None:
    with pytest.raises(MemoryNotFoundError):
        adapter.update_memory("nope", "text", "user")
    assert count_rows(adapter.database.path, "audit_events") == 0


def test_update_is_refused_when_the_memory_is_tampered(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("policy: refunds need approval", "user")
    execute_sql(
        adapter.database.path,
        "UPDATE store_items SET content = ? WHERE memory_id = ?",
        ("policy: refunds are automatic", record.memory_id),
    )

    with pytest.raises(IntegrityError, match="update refused"):
        adapter.update_memory(record.memory_id, "policy: new text", "user")

    assert len(adapter.list_versions(record.memory_id)) == 1
    stored = query_sql(
        adapter.database.path,
        "SELECT content FROM store_items WHERE memory_id = ?",
        (record.memory_id,),
    )
    assert stored == [("policy: refunds are automatic",)]  # evidence not overwritten
    refusals = adapter.list_audit_events("UPDATE_REFUSED")
    assert len(refusals) == 1  # the refusal itself was committed
    assert refusals[0].details["status"] == "TAMPERED"


# --------------------------------------------------------------------------- #
# transactional consistency
# --------------------------------------------------------------------------- #


class ExplodingStore(SimpleVectorStore):
    """A store whose writes start failing after ``allowed`` successful puts."""

    def __init__(self, allowed: int) -> None:
        self.allowed = allowed
        self.puts = 0

    def put(self, conn: sqlite3.Connection, memory_id: str, content: str) -> None:
        """Fail once the allowance is used up."""
        self.puts += 1
        if self.puts > self.allowed:
            raise RuntimeError("store down")
        super().put(conn, memory_id, content)


def test_failed_store_write_rolls_back_the_ledger_on_add(tmp_path: Path) -> None:
    adapter = AuditMemoryAdapter.open(
        tmp_path / "x.db", ExplodingStore(allowed=0), id_factory=make_id_factory()
    )

    with pytest.raises(RuntimeError, match="store down"):
        adapter.add_memory("never persisted", "user")

    for table in ("memories", "memory_versions", "audit_events", "store_items"):
        assert count_rows(adapter.database.path, table) == 0


def test_failed_store_write_rolls_back_the_ledger_on_update(tmp_path: Path) -> None:
    adapter = AuditMemoryAdapter.open(
        tmp_path / "x.db", ExplodingStore(allowed=1), id_factory=make_id_factory()
    )
    record = adapter.add_memory("stable content", "user")

    with pytest.raises(RuntimeError, match="store down"):
        adapter.update_memory(record.memory_id, "new content", "user")

    assert [v.content for v in adapter.list_versions(record.memory_id)] == [
        "stable content"
    ]
    assert adapter.verify_integrity(record.memory_id).status == "VALID"
    assert len(adapter.list_audit_events("MEMORY_UPDATED")) == 0


# --------------------------------------------------------------------------- #
# SQLite connection management
# --------------------------------------------------------------------------- #

INSERT_MEMORY = (
    "INSERT INTO memories (memory_id, current_version_id, created_at) "
    "VALUES ('m1', NULL, 't')"
)


def test_transaction_commits_on_success_and_closes_the_connection(
    tmp_path: Path,
) -> None:
    db = Database(tmp_path / "db.sqlite")
    held: list[sqlite3.Connection] = []

    with db.transaction() as conn:
        held.append(conn)
        conn.execute(INSERT_MEMORY)

    with pytest.raises(sqlite3.ProgrammingError):
        held[0].execute("SELECT 1")  # closed
    with db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == 1


def test_transaction_rolls_back_and_closes_on_failure(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    held: list[sqlite3.Connection] = []

    with pytest.raises(KeyError):
        with db.transaction() as conn:
            held.append(conn)
            conn.execute(INSERT_MEMORY)
            raise KeyError("boom")

    with pytest.raises(sqlite3.ProgrammingError):
        held[0].execute("SELECT 1")
    with db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == 0


def test_sqlite_errors_become_storage_errors_and_roll_back(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    held: list[sqlite3.Connection] = []

    with pytest.raises(StorageError):
        with db.transaction() as conn:
            held.append(conn)
            conn.execute(INSERT_MEMORY)
            conn.execute("INSERT INTO no_such_table VALUES (1)")

    with pytest.raises(sqlite3.ProgrammingError):
        held[0].execute("SELECT 1")
    with db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == 0


def test_foreign_keys_are_enforced_on_every_connection(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    for _ in range(2):
        with db.transaction() as conn:
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
                conn.execute(
                    "INSERT INTO memory_versions (version_id, memory_id, version_number, "
                    "content, content_hash, source, parent_ids, created_at) "
                    "VALUES ('v', 'missing', 1, 'c', ?, 's', '[]', 't')",
                    ("0" * 64,),
                )


def test_wal_mode_is_enabled_at_initialisation(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    Database(path)

    assert query_sql(str(path), "PRAGMA journal_mode") == [("wal",)]


def test_reopening_an_initialised_database_keeps_its_data(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    first = AuditMemoryAdapter.open(path, id_factory=make_id_factory())
    record = first.add_memory("persisted fact", "user")

    second = AuditMemoryAdapter.open(path)

    assert second.get_memory("persisted") == [record]


@pytest.mark.parametrize("path", [":memory:", "", "file::memory:?cache=shared"])
def test_in_memory_databases_are_rejected(path: str) -> None:
    with pytest.raises(ValueError, match="file-backed"):
        Database(path)


def test_unsupported_schema_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    Database(path)
    execute_sql(str(path), "PRAGMA user_version = 99")

    with pytest.raises(StorageError, match="schema version"):
        Database(path)


# --------------------------------------------------------------------------- #
# inspection API
# --------------------------------------------------------------------------- #


def test_audit_trail_lists_events_in_insertion_order(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("trail fact", "user")
    adapter.update_memory(record.memory_id, "trail fact v2", "user")
    adapter.get_memory("trail")

    types = [event.event_type for event in adapter.list_audit_events()]

    assert types == ["MEMORY_ADDED", "MEMORY_UPDATED", "READ"]
    assert [e.memory_id for e in adapter.list_audit_events("MEMORY_ADDED")] == [
        record.memory_id
    ]