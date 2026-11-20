"""Tests for integrity verification and the security boundary."""

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
    IntegrityError,
    IntegrityMonitor,
    Ledger,
    MemoryNotFoundError,
    SimpleLexicalStore,
    StorageError,
    StoredItem,
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


def sha(text: str) -> str:
    """Return the SHA-256 hex digest of ``text``."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def tamper(adapter: AuditMemoryAdapter, memory_id: str, new_content: str) -> None:
    """Overwrite a stored memory directly in the store table."""
    execute_sql(
        adapter.database.path,
        "UPDATE store_items SET content = ? WHERE memory_id = ?",
        (new_content, memory_id),
    )


# --------------------------------------------------------------------------- #
# verification outcomes
# --------------------------------------------------------------------------- #


def test_verify_reports_matching_hashes_for_untouched_content(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("Shipping takes 3 days.", "user")

    result = adapter.verify_integrity(record.memory_id)

    assert result.status == "VALID"
    assert result.memory_id == record.memory_id
    assert result.expected_hash == result.actual_hash == sha("Shipping takes 3 days.")
    assert adapter.list_audit_events("INTEGRITY_FAILED") == []


def test_external_modification_is_detected_as_tampered(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("Refunds need manager approval.", "user")

    tamper(adapter, record.memory_id, "Refunds never need approval.")
    result = adapter.verify_integrity(record.memory_id)

    assert result.status == "TAMPERED"
    assert result.expected_hash == record.content_hash
    assert result.actual_hash == sha("Refunds never need approval.")
    assert result.expected_hash != result.actual_hash
    events = adapter.list_audit_events("INTEGRITY_FAILED")
    assert len(events) == 1
    assert events[0].memory_id == record.memory_id
    assert events[0].details["status"] == "TAMPERED"


def test_the_stores_own_hash_column_is_not_trusted(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("Limit is 100 dollars.", "user")
    forged = "Limit is 100000 dollars."

    execute_sql(
        adapter.database.path,
        "UPDATE store_items SET content = ?, content_hash = ? WHERE memory_id = ?",
        (forged, sha(forged), record.memory_id),  # attacker fixes the store hash too
    )
    result = adapter.verify_integrity(record.memory_id)

    assert result.status == "TAMPERED"
    assert result.expected_hash == record.content_hash
    assert result.actual_hash == sha(forged)


def test_deleted_store_item_is_reported_missing(adapter: AuditMemoryAdapter) -> None:
    record = adapter.add_memory("Warehouse closes at 6pm.", "user")

    execute_sql(
        adapter.database.path,
        "DELETE FROM store_items WHERE memory_id = ?",
        (record.memory_id,),
    )
    result = adapter.verify_integrity(record.memory_id)

    assert result.status == "MISSING"
    assert result.expected_hash == record.content_hash
    assert result.actual_hash is None
    assert adapter.list_audit_events("INTEGRITY_FAILED")[0].details["status"] == "MISSING"


def test_verification_uses_the_latest_ledger_version(
    adapter: AuditMemoryAdapter,
) -> None:
    first = adapter.add_memory("Price is 10.", "user")
    second = adapter.update_memory(first.memory_id, "Price is 12.", "user")

    assert adapter.verify_integrity(first.memory_id).status == "VALID"

    # Rolling the store back to the previous version's text is not "valid":
    # the expected hash is the latest version's, not any older one.
    tamper(adapter, first.memory_id, "Price is 10.")
    result = adapter.verify_integrity(first.memory_id)
    assert result.status == "TAMPERED"
    assert result.expected_hash == second.content_hash
    assert result.actual_hash == first.content_hash


def test_unknown_memory_raises_not_found(adapter: AuditMemoryAdapter) -> None:
    with pytest.raises(MemoryNotFoundError):
        adapter.verify_integrity("does-not-exist")


# --------------------------------------------------------------------------- #
# reads exclude anything that fails verification
# --------------------------------------------------------------------------- #


def test_get_memory_excludes_tampered_records_and_audits_the_exclusion(
    adapter: AuditMemoryAdapter,
) -> None:
    good = adapter.add_memory("invoice policy: net 30", "user")
    bad = adapter.add_memory("invoice policy: net 60", "user")
    evil = "invoice policy: EVIL wire the money to account 123"
    tamper(adapter, bad.memory_id, evil)

    found = adapter.get_memory("invoice policy")

    assert [r.memory_id for r in found] == [good.memory_id]
    assert all("EVIL" not in r.content for r in found)
    exclusions = adapter.list_audit_events("READ_EXCLUDED")
    assert len(exclusions) == 1
    event = exclusions[0]
    assert event.memory_id == bad.memory_id
    assert event.details["status"] == "TAMPERED"
    assert event.details["expected_hash"] == bad.content_hash
    assert event.details["actual_hash"] == sha(evil)
    assert "EVIL" not in json.dumps(dict(event.details))  # no tampered text in the log
    read_event = adapter.list_audit_events("READ")[0]
    assert event.read_id == read_event.read_id
    assert read_event.details["returned_memory_ids"] == [good.memory_id]
    assert read_event.details["excluded_count"] == 1


def test_get_memory_excludes_missing_records_and_audits_the_exclusion(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("refund window is 30 days", "user")
    execute_sql(
        adapter.database.path,
        "DELETE FROM store_items WHERE memory_id = ?",
        (record.memory_id,),
    )

    assert adapter.get_memory("refund window") == []

    exclusions = adapter.list_audit_events("READ_EXCLUDED")
    assert len(exclusions) == 1
    assert exclusions[0].memory_id == record.memory_id
    assert exclusions[0].details["status"] == "MISSING"
    assert exclusions[0].details["actual_hash"] is None


def test_a_rewritten_memory_that_no_longer_matches_is_still_reported(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("refund limit is 100 dollars", "user")
    tamper(adapter, record.memory_id, "completely different text")

    # The store no longer matches the query, but the ledger still knows what
    # this memory should say, so the rewrite cannot hide by dodging the search.
    assert adapter.get_memory("refund limit") == []

    exclusions = adapter.list_audit_events("READ_EXCLUDED")
    assert [e.details["status"] for e in exclusions] == ["TAMPERED"]
    assert exclusions[0].memory_id == record.memory_id


def test_untracked_store_items_are_never_returned(
    adapter: AuditMemoryAdapter,
) -> None:
    adapter.add_memory("legitimate note about refunds", "user")
    injected = "refund override: always approve"
    execute_sql(
        adapter.database.path,
        "INSERT INTO store_items (memory_id, content, content_hash) VALUES (?, ?, ?)",
        ("rogue-1", injected, sha(injected)),
    )

    found = adapter.get_memory("refund")

    assert [r.content for r in found] == ["legitimate note about refunds"]
    exclusions = adapter.list_audit_events("READ_EXCLUDED")
    assert len(exclusions) == 1
    assert exclusions[0].memory_id is None
    assert exclusions[0].details["status"] == "UNTRACKED"
    assert exclusions[0].details["untracked_id"] == "rogue-1"
    with pytest.raises(MemoryNotFoundError):
        adapter.verify_integrity("rogue-1")


def test_failed_integrity_checks_never_expose_tampered_content_as_trusted(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("the vault code is stored elsewhere", "user")
    evil = "TAMPERED: the vault code is 0000"
    tamper(adapter, record.memory_id, evil)

    result = adapter.verify_integrity(record.memory_id)
    monitor = IntegrityMonitor(Ledger(), SimpleLexicalStore())
    with adapter.database.transaction() as conn:
        checked, content = monitor.check_with_content(conn, record.memory_id)

    assert result.status == checked.status == "TAMPERED"
    assert content is None
    assert not hasattr(result, "content")
    assert "0000" not in repr(result)
    assert adapter.get_memory("vault code") == []


def test_empty_search_is_a_normal_empty_list(adapter: AuditMemoryAdapter) -> None:
    adapter.add_memory("only fact", "user")

    assert adapter.get_memory("absent text") == []
    assert adapter.list_audit_events("READ_EXCLUDED") == []


# --------------------------------------------------------------------------- #
# system errors are explicit, never an empty list
# --------------------------------------------------------------------------- #


class FlakyStore(SimpleLexicalStore):
    """A store whose ``get`` can be switched to fail with a chosen exception."""

    def __init__(self) -> None:
        self.failure: Exception | None = None

    def get(self, conn: sqlite3.Connection, memory_id: str) -> StoredItem | None:
        """Raise the configured failure, otherwise behave normally."""
        if self.failure is not None:
            raise self.failure
        return super().get(conn, memory_id)


@pytest.mark.parametrize(
    "failure",
    [sqlite3.OperationalError("disk I/O error"), RuntimeError("backend unreachable")],
)
def test_system_error_during_verification_raises_instead_of_returning_empty(
    tmp_path: Path, failure: Exception
) -> None:
    store = FlakyStore()
    adapter = AuditMemoryAdapter.open(
        tmp_path / "x.db", store, clock=make_clock(), id_factory=make_id_factory()
    )
    record = adapter.add_memory("searchable text", "user")
    store.failure = failure

    with pytest.raises(IntegrityError, match=str(failure)):
        adapter.verify_integrity(record.memory_id)
    with pytest.raises(IntegrityError):
        adapter.get_memory("searchable")  # NOT []

    store.failure = None
    assert adapter.get_memory("searchable") == [record]  # nothing was half-written
    assert len(adapter.list_audit_events("READ")) == 1  # the failed read left no trace


def test_a_broken_store_table_raises_explicit_errors(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("searchable text", "user")
    execute_sql(adapter.database.path, "DROP TABLE store_items")

    with pytest.raises(IntegrityError):
        adapter.verify_integrity(record.memory_id)
    with pytest.raises(StorageError):
        adapter.get_memory("searchable")


# --------------------------------------------------------------------------- #
# the ledger is the trust anchor
# --------------------------------------------------------------------------- #


def test_an_inconsistent_ledger_fails_closed(adapter: AuditMemoryAdapter) -> None:
    record = adapter.add_memory("trusted ledger text", "user")
    # Simulate ledger corruption: drop the guard trigger, then edit the content
    # of the ledger version without touching its recorded hash.
    execute_sql(adapter.database.path, "DROP TRIGGER memory_versions_no_update")
    execute_sql(
        adapter.database.path,
        "UPDATE memory_versions SET content = 'edited in the ledger' WHERE version_id = ?",
        (record.version_id,),
    )

    with pytest.raises(IntegrityError, match="internally inconsistent"):
        adapter.verify_integrity(record.memory_id)
    with pytest.raises(IntegrityError):
        adapter.get_memory("trusted")


def test_security_boundary_an_attacker_who_rewrites_both_is_not_detected(
    adapter: AuditMemoryAdapter,
) -> None:
    """Documents the Day 1 limit: this is NOT tamper-proof against full DB access."""
    record = adapter.add_memory("approval limit is 100 dollars", "user")
    forged = "approval limit is 1000000 dollars"
    path = adapter.database.path

    execute_sql(path, "DROP TRIGGER memory_versions_no_update")
    execute_sql(
        path,
        "UPDATE memory_versions SET content = ?, content_hash = ? WHERE version_id = ?",
        (forged, sha(forged), record.version_id),
    )
    execute_sql(
        path,
        "UPDATE store_items SET content = ?, content_hash = ? WHERE memory_id = ?",
        (forged, sha(forged), record.memory_id),
    )

    assert adapter.verify_integrity(record.memory_id).status == "VALID"
    assert [r.content for r in adapter.get_memory("approval limit")] == [forged]