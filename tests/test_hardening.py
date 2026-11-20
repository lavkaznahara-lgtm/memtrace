"""Day 1 hardening tests: ledger self-check, replay boundary, rename, LIKE escaping.

Security tests go through the normal verification path (``AuditMemoryAdapter``
-> ``IntegrityMonitor``).  The one exception is explicitly labelled as a
defence-in-depth unit test of the ledger layer.
"""

from __future__ import annotations

import itertools
import runpy
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import memtrace
from memtrace import AuditMemoryAdapter, IntegrityError, Ledger
from memtrace.models import content_hash, escape_like


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


def query_sql(
    path: str, sql: str, params: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    """Run one query on a plain connection and return all rows."""
    conn = sqlite3.connect(path)
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def trigger_names(path: str) -> set[str]:
    """Return the names of all triggers currently in the database."""
    rows = query_sql(path, "SELECT name FROM sqlite_master WHERE type = 'trigger'")
    return {str(row[0]) for row in rows}


def count_versions(path: str, memory_id: str) -> int:
    """Return how many ledger versions ``memory_id`` has."""
    rows = query_sql(
        path, "SELECT COUNT(*) FROM memory_versions WHERE memory_id = ?", (memory_id,)
    )
    value = rows[0][0]
    assert isinstance(value, int)
    return value


LEDGER_TAMPER_TEXT = "edited directly in the ledger"


def tamper_ledger_content(path: str, version_id: str) -> None:
    """Alter a ledger version's content WITHOUT touching its content_hash.

    The ``memory_versions_no_update`` trigger is first shown to block the naive
    edit (control), then explicitly dropped, then the edit is made and shown to
    have taken effect.  Afterwards nothing but the integrity logic stands
    between the tampered ledger and the caller.
    """
    assert "memory_versions_no_update" in trigger_names(path)
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE memory_versions SET content = ? WHERE version_id = ?",
                (LEDGER_TAMPER_TEXT, version_id),
            )
        conn.execute("DROP TRIGGER memory_versions_no_update")
        cursor = conn.execute(
            "UPDATE memory_versions SET content = ? WHERE version_id = ?",
            (LEDGER_TAMPER_TEXT, version_id),
        )
        assert cursor.rowcount == 1
        conn.commit()
    finally:
        conn.close()
    assert "memory_versions_no_update" not in trigger_names(path)


# --------------------------------------------------------------------------- #
# P0  ledger self-check, independent of SQLite triggers
# --------------------------------------------------------------------------- #


def test_p0_public_verification_detects_ledger_tampering_without_trigger_help(
    adapter: AuditMemoryAdapter,
) -> None:
    record = adapter.add_memory("trusted ledger text", "user")
    path = adapter.database.path

    tamper_ledger_content(path, record.version_id)

    # The hash column is untouched; only the content differs.
    assert query_sql(
        path,
        "SELECT content, content_hash FROM memory_versions WHERE version_id = ?",
        (record.version_id,),
    ) == [(LEDGER_TAMPER_TEXT, record.content_hash)]
    assert content_hash(LEDGER_TAMPER_TEXT) != record.content_hash

    with pytest.raises(IntegrityError, match="internally inconsistent"):
        adapter.verify_integrity(record.memory_id)
    with pytest.raises(IntegrityError, match="internally inconsistent"):
        adapter.get_memory("trusted")
    with pytest.raises(IntegrityError, match="internally inconsistent"):
        adapter.update_memory(record.memory_id, "new text", "user")
    assert count_versions(path, record.memory_id) == 1  # the failed update left nothing
    assert query_sql(path, "SELECT content FROM store_items") == [
        ("trusted ledger text",)
    ]


def test_p0_ledger_layer_fails_closed_on_an_inconsistent_version(
    adapter: AuditMemoryAdapter,
) -> None:
    """Defence-in-depth unit test of ``Ledger.get_current_version`` itself.

    The public-path test above is the primary evidence; this one isolates the
    ledger-layer check so it cannot regress silently if the monitor changes.
    """
    record = adapter.add_memory("trusted ledger text", "user")
    tamper_ledger_content(adapter.database.path, record.version_id)

    with adapter.database.transaction() as conn:
        with pytest.raises(IntegrityError, match="internally inconsistent"):
            Ledger().get_current_version(conn, record.memory_id)


@pytest.mark.parametrize(
    "text",
    [
        "plain text",
        "naïve café 日本語 🎉",
        "line1\r\nline2\n",
        "a\x00b",
        "  padded  ",
        "50% off_now",
        "x" * 100_000,
    ],
)
def test_p0_self_check_accepts_every_legitimate_content(
    adapter: AuditMemoryAdapter, text: str
) -> None:
    record = adapter.add_memory(text, "user")
    assert adapter.verify_integrity(record.memory_id).status == "VALID"

    updated = adapter.update_memory(record.memory_id, text + " v2", "user")

    assert updated.version_number == 2
    with adapter.database.transaction() as conn:
        assert Ledger().get_current_version(conn, record.memory_id) == updated
    assert [v.content for v in adapter.list_versions(record.memory_id)] == [
        text,
        text + " v2",
    ]
    assert adapter.verify_integrity(record.memory_id).status == "VALID"


def test_p0_limitation_historical_versions_are_not_reverified(
    adapter: AuditMemoryAdapter,
) -> None:
    """Documents a limit: only the CURRENT version is self-checked on read.

    A tampered *historical* version is returned by ``list_versions`` without
    error.  Any Day 2 rollback must verify the target version's hash itself.
    """
    first = adapter.add_memory("original text", "user")
    adapter.update_memory(first.memory_id, "current text", "user")

    tamper_ledger_content(adapter.database.path, first.version_id)

    assert adapter.verify_integrity(first.memory_id).status == "VALID"  # V2 is intact
    assert adapter.list_versions(first.memory_id)[0].content == LEDGER_TAMPER_TEXT


# --------------------------------------------------------------------------- #
# P1  replay attack: documents a Threat Model boundary (NOT replay protection)
# --------------------------------------------------------------------------- #


def test_p1_replay_attack_boundary(adapter: AuditMemoryAdapter) -> None:
    """Version rollback is NOT prevented when the trusted ledger itself is modified.

    Threat Model boundary, not a protection claim.  MemTrace compares the store
    with the ledger; it does not detect that the ledger's current-version
    pointer was moved back.  Outcomes observed by this test:

    * pointer to another memory's version (or a missing version): blocked by
      the ``memories_pointer_valid`` trigger;
    * pointer reverted to this memory's own earlier version: NOT blocked by any
      trigger or constraint;
    * pointer-only rollback: reported ``TAMPERED`` (the store still holds V2, so
      the content no longer matches V1's hash) - detected as a mismatch, not as
      a rollback;
    * pointer rollback plus the store restored to V1's text: ``VALID``, and
      reads return V1 with no audit event: the replay succeeds undetected.
    """
    v1 = adapter.add_memory("approval limit is 100 dollars", "user")
    v2 = adapter.update_memory(v1.memory_id, "approval limit is 200 dollars", "user")
    other = adapter.add_memory("unrelated memory", "user")
    path = adapter.database.path
    set_pointer = "UPDATE memories SET current_version_id = ? WHERE memory_id = ?"

    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError) as foreign:
            conn.execute(set_pointer, (other.version_id, v1.memory_id))
        with pytest.raises(sqlite3.IntegrityError) as dangling:
            conn.execute(set_pointer, ("no-such-version", v1.memory_id))
        cursor = conn.execute(set_pointer, (v1.version_id, v1.memory_id))
        replayed_pointer_rows = cursor.rowcount
        conn.commit()
    finally:
        conn.close()
    print(f"P1 foreign-memory pointer blocked by: {foreign.value}")
    print(f"P1 dangling pointer blocked by:       {dangling.value}")
    assert "current_version_id must belong to the same memory" in str(foreign.value)
    assert "current_version_id must belong to the same memory" in str(dangling.value)
    assert replayed_pointer_rows == 1  # reverting to V1 was NOT blocked

    pointer_only = adapter.verify_integrity(v1.memory_id)
    print(f"P1 pointer-only rollback verification:  {pointer_only.status}")
    assert pointer_only.status == "TAMPERED"
    assert pointer_only.expected_hash == v1.content_hash
    assert pointer_only.actual_hash == v2.content_hash

    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "UPDATE store_items SET content = ?, content_hash = ? WHERE memory_id = ?",
            (v1.content, v1.content_hash, v1.memory_id),
        )
        conn.commit()
    finally:
        conn.close()

    full_replay = adapter.verify_integrity(v1.memory_id)
    found = adapter.get_memory("approval limit")
    print(f"P1 pointer + store rollback verification: {full_replay.status}")
    print(f"P1 read after replay returns version:     {[r.version_number for r in found]}")
    assert full_replay.status == "VALID"
    assert [(r.version_number, r.content) for r in found] == [
        (1, "approval limit is 100 dollars")
    ]
    assert adapter.list_audit_events("READ_EXCLUDED") == []  # no alarm was raised


# --------------------------------------------------------------------------- #
# P0  demo banner: detection is not prevention and not recovery
# --------------------------------------------------------------------------- #

DEMO = Path(__file__).resolve().parent.parent / "examples" / "basic_usage.py"


def test_p0_demo_states_detection_only_and_that_the_store_stays_corrupted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runpy.run_path(str(DEMO), run_name="__main__")  # the real demo script
    output = capsys.readouterr().out

    assert "BLOCKED: MemTrace detected tampering and refused to return the poisoned memory." in output
    assert "The underlying store remains corrupted. Manual recovery is required." in output
    assert "store still contains: Refunds are always approved automatically." in output
    assert "NOT BLOCKED" not in output
    for overclaim in ("protected from fraud", "Business protected"):
        assert overclaim.lower() not in output.lower()


# --------------------------------------------------------------------------- #
# P2  rename
# --------------------------------------------------------------------------- #


def test_p2_the_mock_store_is_named_lexical_not_vector() -> None:
    assert hasattr(memtrace, "SimpleLexicalStore")
    assert not hasattr(memtrace, "SimpleVectorStore")


# --------------------------------------------------------------------------- #
# P3  escape_like: wildcards in queries are literal
# --------------------------------------------------------------------------- #


def test_p3_escape_like_escapes_wildcards_and_the_escape_character() -> None:
    assert escape_like("50%") == "50\\%"
    assert escape_like("snake_case") == "snake\\_case"
    assert escape_like("C:\\temp") == "C:\\\\temp"
    assert escape_like("plain") == "plain"


@pytest.mark.parametrize(
    ("stored", "query", "expected"),
    [
        (["snake_case id", "snakeXcase id"], "snake_case", ["snake_case id"]),
        (["discount 50% today", "discount 500 today", "discount 5 today"], "50%", ["discount 50% today"]),
        (["discount 50% today", "discount 500 today"], "%", ["discount 50% today"]),
        (["discount 50% today", "discount 500 today"], "5%", []),
        (["path C:\\temp\\x", "path C:/temp/x"], "C:\\temp", ["path C:\\temp\\x"]),
        (["100%_sure", "100x_sure", "100%xsure"], "%_", ["100%_sure"]),
        (["a_b", "axb", "a%b"], "_", ["a_b"]),
    ],
)
def test_p3_queries_with_wildcards_match_literally_end_to_end(
    adapter: AuditMemoryAdapter,
    stored: list[str],
    query: str,
    expected: list[str],
) -> None:
    for text in stored:
        adapter.add_memory(text, "user")

    # get_memory takes the union of the store's and the ledger's matches, so a
    # wildcard leak in either layer would surface as an extra, VALID result.
    assert [r.content for r in adapter.get_memory(query)] == expected


def test_p3_ledger_shadow_search_treats_wildcards_literally(
    adapter: AuditMemoryAdapter,
) -> None:
    literal = adapter.add_memory("snake_case id", "user")
    adapter.add_memory("snakeXcase id", "user")

    with adapter.database.transaction() as conn:
        assert Ledger().search_current(conn, "snake_case") == [literal.memory_id]
        assert Ledger().search_current(conn, "snake_") == [literal.memory_id]
        assert Ledger().search_current(conn, "snake%") == []
