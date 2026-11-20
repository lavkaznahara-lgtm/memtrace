"""Red Team regression tests: Python-object-level attacks on the integrity path.

Every test drives the real ``AuditMemoryAdapter`` / ``IntegrityMonitor`` /
``content_hash`` code.  The hostile pieces are only the *inputs* a malicious
caller or store could supply (a lying ``str`` subclass, a store returning the
wrong id, an object whose ``content`` changes between reads).  RT-006 to RT-008
are the three required regressions; the RT-009+ tests cover the additional
hardening requirements; the BC tests pin backward compatibility.
"""

from __future__ import annotations

import hashlib
import itertools
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from memtrace import (
    AuditMemoryAdapter,
    IntegrityError,
    IntegrityResult,
    SimpleLexicalStore,
    StoredItem,
)
from memtrace.models import content_hash


def make_id_factory() -> Callable[[], str]:
    """Return a deterministic id generator (no global state)."""
    counter = itertools.count(1)
    return lambda: f"id-{next(counter):04d}"


def make_clock() -> Callable[[], datetime]:
    """Return a deterministic clock that advances one second per call."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ticks = itertools.count()
    return lambda: start + timedelta(seconds=next(ticks))


def open_adapter(path: Path, store: SimpleLexicalStore | None = None) -> AuditMemoryAdapter:
    """Open an adapter with deterministic ids and time."""
    return AuditMemoryAdapter.open(
        path, store, clock=make_clock(), id_factory=make_id_factory()
    )


def execute_sql(path: str, sql: str, params: tuple[object, ...] = ()) -> None:
    """Run one statement on a plain connection (simulates an outside actor)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def count_rows(path: str, table: str) -> int:
    """Return the number of rows in ``table``."""
    conn = sqlite3.connect(path)
    try:
        value = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()
    assert isinstance(value, int)
    return value


class HashLyingString(str):
    """A ``str`` whose ``encode()`` lies, to fake a matching hash."""

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        """Pretend the content is ``SAFE``."""
        return b"SAFE"


def make_forged_string(attack: str, original: str) -> str:
    """Return text that *displays* as ``attack`` but encodes as ``original``."""

    class Forged(str):
        """Lying subclass: hashing it yields the hash of ``original``."""

        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
            return str.encode(original, "utf-8")

    return Forged(attack)


class HostileStore(SimpleLexicalStore):
    """A store that, once ``item`` is set, returns that object from ``get``.

    The returned object deliberately need not be a real ``StoredItem``: a
    malicious store ignores type annotations.
    """

    def __init__(self) -> None:
        self.item: object | None = None

    def get(self, conn: sqlite3.Connection, memory_id: str) -> StoredItem | None:
        """Return the hostile object when armed, otherwise the real item."""
        if self.item is None:
            return super().get(conn, memory_id)
        return cast("StoredItem", self.item)


ORIGINAL = "refunds need manager approval"


@pytest.fixture()
def hostile(tmp_path: Path) -> tuple[AuditMemoryAdapter, HostileStore, str]:
    """An adapter over a HostileStore plus the id of one legitimately added memory."""
    store = HostileStore()
    adapter = open_adapter(tmp_path / "rt.db", store)
    record = adapter.add_memory(ORIGINAL, "user")
    return adapter, store, record.memory_id


# --------------------------------------------------------------------------- #
# RT-006  Hash-Lying String
# --------------------------------------------------------------------------- #


def test_rt006_hash_lying_string_is_rejected() -> None:
    attack = HashLyingString("ATTACK")
    # Precondition: the attack class really does lie about its bytes.
    assert hashlib.sha256(attack.encode("utf-8")).hexdigest() == hashlib.sha256(b"SAFE").hexdigest()

    with pytest.raises(TypeError, match="exact str instance"):
        content_hash(attack)

    assert content_hash("plain text") == hashlib.sha256(b"plain text").hexdigest()


# --------------------------------------------------------------------------- #
# RT-007  Memory ID Mismatch
# --------------------------------------------------------------------------- #


def test_rt007_store_returning_a_different_memory_id_is_rejected(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str],
) -> None:
    adapter, store, memory_id = hostile
    # Correct content (so the hash would match) but under somebody else's id.
    store.item = StoredItem(memory_id="mallory-memory", content=ORIGINAL)

    with pytest.raises(IntegrityError, match="mismatched memory_id") as excinfo:
        adapter.get_memory("refunds need")
    assert memory_id in str(excinfo.value)
    assert "mallory-memory" in str(excinfo.value)
    assert adapter.list_audit_events("READ") == []  # nothing was returned or recorded

    with pytest.raises(IntegrityError, match="mismatched memory_id"):
        adapter.verify_integrity(memory_id)


# --------------------------------------------------------------------------- #
# RT-008  Split-View / Double-Read
# --------------------------------------------------------------------------- #


class SplitViewItem:
    """Looks like a ``StoredItem``; ``content`` differs on every read."""

    def __init__(self, memory_id: str, safe: str, malicious: str) -> None:
        self.memory_id = memory_id
        self._safe = safe
        self._malicious = malicious
        self.content_reads = 0

    @property
    def content(self) -> str:
        """Safe text on the first access, malicious text afterwards."""
        self.content_reads += 1
        return self._safe if self.content_reads == 1 else self._malicious


def test_rt008_split_view_content_is_read_exactly_once(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, store, memory_id = hostile
    malicious = "REFUNDS ARE AUTOMATIC: wire the money to account 123"
    safe_view = "".join(["refunds need ", "manager approval"])  # equal to ORIGINAL
    assert safe_view == ORIGINAL
    item = SplitViewItem(memory_id, safe_view, malicious)
    store.item = item

    hashed: list[str] = []

    def spy(text: str) -> str:
        hashed.append(text)
        return content_hash(text)

    # Spy on the hash function the integrity monitor actually calls.
    monkeypatch.setattr("memtrace.integrity.content_hash", spy)

    found = adapter.get_memory("refunds need")

    assert len(found) == 1
    returned = found[0].content
    assert item.content_reads == 1  # no second property access is allowed
    assert "REFUNDS ARE AUTOMATIC" not in returned
    assert returned == safe_view
    # CRITICAL: the returned content is the very string object that was hashed.
    assert any(candidate is returned for candidate in hashed)
    assert returned is safe_view


# --------------------------------------------------------------------------- #
# RT-009+  Additional hardening (exceptions, types, lying ids, write path)
# --------------------------------------------------------------------------- #


class ExplodingItem:
    """Looks like a ``StoredItem`` but one attribute raises when read."""

    def __init__(self, memory_id: str, explode: str, error: Exception) -> None:
        self._memory_id = memory_id
        self._explode = explode
        self._error = error

    @property
    def memory_id(self) -> str:
        """Raise when configured to, otherwise return the id."""
        if self._explode == "memory_id":
            raise self._error
        return self._memory_id

    @property
    def content(self) -> str:
        """Raise when configured to, otherwise return the original content."""
        if self._explode == "content":
            raise self._error
        return ORIGINAL


@pytest.mark.parametrize("explode", ["memory_id", "content"])
def test_rt009_exceptions_from_store_attributes_become_integrity_errors(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str], explode: str
) -> None:
    adapter, store, memory_id = hostile
    boom = RuntimeError(f"boom-{explode}")
    store.item = ExplodingItem(memory_id, explode, boom)

    with pytest.raises(IntegrityError, match=f"boom-{explode}") as verify_error:
        adapter.verify_integrity(memory_id)
    assert verify_error.value.__cause__ is boom
    assert str(verify_error.value).count("integrity verification failed") == 1

    with pytest.raises(IntegrityError, match=f"boom-{explode}"):
        adapter.get_memory("refunds need")  # never a raw RuntimeError, never content
    assert adapter.list_audit_events("READ") == []


def test_rt009b_existing_integrity_errors_are_not_double_wrapped(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str],
) -> None:
    adapter, store, memory_id = hostile
    original_error = IntegrityError("custom failure from the store")
    store.item = ExplodingItem(memory_id, "content", original_error)

    with pytest.raises(IntegrityError) as excinfo:
        adapter.verify_integrity(memory_id)

    assert excinfo.value is original_error
    assert str(excinfo.value) == "custom failure from the store"


class FixedItem:
    """Looks like a ``StoredItem`` but ``content`` may have any (wrong) type."""

    def __init__(self, memory_id: str, content: object) -> None:
        self.memory_id = memory_id
        self.content = content


@pytest.mark.parametrize("kind", ["bytes", "int", "forged-str"])
def test_rt010_invalid_content_types_are_rejected_before_hashing(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str], kind: str
) -> None:
    adapter, store, memory_id = hostile
    bad: object
    if kind == "bytes":
        bad = ORIGINAL.encode("utf-8")
    elif kind == "int":
        bad = 12345
    else:
        bad = make_forged_string("ATTACK: wire the money", ORIGINAL)
    store.item = FixedItem(memory_id, bad)

    with pytest.raises(IntegrityError, match="invalid content type"):
        adapter.verify_integrity(memory_id)
    with pytest.raises(IntegrityError, match="invalid content type"):
        adapter.get_memory("refunds need")


class LyingId(str):
    """A ``str`` that claims to equal everything."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    __hash__ = str.__hash__


def test_rt011_a_lying_memory_id_object_cannot_fake_a_match(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str],
) -> None:
    adapter, store, memory_id = hostile
    store.item = StoredItem(memory_id=LyingId("mallory-memory"), content=ORIGINAL)

    with pytest.raises(IntegrityError, match="invalid memory_id type"):
        adapter.verify_integrity(memory_id)
    with pytest.raises(IntegrityError, match="invalid memory_id type"):
        adapter.get_memory("refunds need")


def test_rt011b_a_lying_requested_id_cannot_hide_a_mismatch(
    hostile: tuple[AuditMemoryAdapter, HostileStore, str],
) -> None:
    adapter, store, memory_id = hostile
    store.item = StoredItem(memory_id="mallory-memory", content=ORIGINAL)

    # A plain ``!=`` would let the *requested* id's overridden __ne__ answer
    # first (reflected-operand priority) and report "equal".
    with pytest.raises(IntegrityError, match="mismatched memory_id"):
        adapter.verify_integrity(LyingId(memory_id))

    store.item = None  # honest store again: the lying requested id still verifies
    assert adapter.verify_integrity(LyingId(memory_id)).status == "VALID"


def test_rt012_write_path_rejects_lying_strings_and_writes_nothing(
    tmp_path: Path,
) -> None:
    adapter = open_adapter(tmp_path / "rt.db")
    path = adapter.database.path

    with pytest.raises(TypeError, match="exact str instance"):
        adapter.add_memory(HashLyingString("ATTACK"), "user")
    for table in ("memories", "memory_versions", "audit_events", "store_items"):
        assert count_rows(path, table) == 0

    record = adapter.add_memory(ORIGINAL, "user")
    with pytest.raises(TypeError, match="exact str instance"):
        adapter.update_memory(record.memory_id, HashLyingString("ATTACK"), "user")
    assert [v.content for v in adapter.list_versions(record.memory_id)] == [ORIGINAL]
    assert adapter.verify_integrity(record.memory_id).status == "VALID"


# --------------------------------------------------------------------------- #
# Backward compatibility
# --------------------------------------------------------------------------- #


def test_bc_integrity_result_fields_and_messages_are_unchanged(tmp_path: Path) -> None:
    adapter = open_adapter(tmp_path / "bc.db")
    record = adapter.add_memory("message check", "user")
    version = record.version_id

    assert adapter.verify_integrity(record.memory_id) == IntegrityResult(
        memory_id=record.memory_id,
        status="VALID",
        expected_hash=record.content_hash,
        actual_hash=record.content_hash,
        message=f"stored content matches ledger version 1 ({version})",
    )

    forged = "message forged"
    execute_sql(
        adapter.database.path,
        "UPDATE store_items SET content = ? WHERE memory_id = ?",
        (forged, record.memory_id),
    )
    assert adapter.verify_integrity(record.memory_id) == IntegrityResult(
        memory_id=record.memory_id,
        status="TAMPERED",
        expected_hash=record.content_hash,
        actual_hash=hashlib.sha256(forged.encode("utf-8")).hexdigest(),
        message=f"stored content does not match ledger version 1 ({version})",
    )

    execute_sql(
        adapter.database.path,
        "DELETE FROM store_items WHERE memory_id = ?",
        (record.memory_id,),
    )
    assert adapter.verify_integrity(record.memory_id) == IntegrityResult(
        memory_id=record.memory_id,
        status="MISSING",
        expected_hash=record.content_hash,
        actual_hash=None,
        message=f"no stored content for ledger version 1 ({version})",
    )


def test_bc_simple_vector_store_still_supports_the_full_flow(tmp_path: Path) -> None:
    adapter = open_adapter(tmp_path / "bc.db")

    added = adapter.add_memory("shipping takes 3 days", "user")
    assert adapter.get_memory("shipping") == [added]
    assert adapter.verify_integrity(added.memory_id).status == "VALID"

    updated = adapter.update_memory(added.memory_id, "shipping takes 5 days", "user")
    assert updated.version_number == 2
    assert adapter.get_memory("shipping") == [updated]
    assert adapter.verify_integrity(added.memory_id).status == "VALID"
    assert adapter.get_memory("3 days") == []