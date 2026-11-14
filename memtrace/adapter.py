"""The audit adapter: wraps an existing memory store and records provenance.

``AuditMemoryAdapter`` sits between an agent and its memory store.  Every write
creates an immutable ledger version; every read is verified against the ledger
before anything is returned, and is itself recorded.

Day 2 will build on the interfaces declared in :mod:`memtrace.models`
(provenance graph, rollback, impact analysis, leave-one-out replay).  None of
that exists yet.

Security boundary: see the README.  Day 1 detects accidental corruption and
unauthorized modifications while the ledger stays intact; it is not
cryptographic tamper-proofing.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from memtrace.integrity import IntegrityMonitor
from memtrace.ledger import (
    EVENT_INTEGRITY_FAILED,
    EVENT_MEMORY_ADDED,
    EVENT_MEMORY_UPDATED,
    EVENT_READ,
    EVENT_READ_EXCLUDED,
    EVENT_UPDATE_REFUSED,
    Database,
    Ledger,
)
from memtrace.models import (
    AuditEvent,
    IntegrityError,
    IntegrityResult,
    MemoryNotFoundError,
    MemoryRecord,
    content_hash,
)
from memtrace.store import MemoryStore, SimpleVectorStore

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]


def _utc_now() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    """Return a fresh random identifier."""
    return uuid.uuid4().hex


def _require_text(name: str, value: str) -> str:
    """Return ``value`` if it is non-blank, encodable text; else raise."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid Unicode text") from exc
    return value


class AuditMemoryAdapter:
    """Audited access to a memory store with an immutable provenance ledger.

    The adapter and the store must share one SQLite :class:`Database` so a
    store write and its ledger entry commit or roll back together.  Use
    :meth:`open` for the usual setup.

    ``clock`` and ``id_factory`` are injectable so tests are deterministic.
    """

    def __init__(
        self,
        database: Database,
        store: MemoryStore,
        *,
        ledger: Ledger | None = None,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        """Wrap ``store``; ``database`` must already contain the store's schema."""
        self._db = database
        self._store = store
        self._ledger = ledger if ledger is not None else Ledger()
        self._monitor = IntegrityMonitor(self._ledger, store)
        self._clock = clock if clock is not None else _utc_now
        self._new_id = id_factory if id_factory is not None else _new_id

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        store: MemoryStore | None = None,
        *,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> AuditMemoryAdapter:
        """Open (creating if needed) a database and wrap ``store`` (default mock)."""
        chosen = store if store is not None else SimpleVectorStore()
        database = Database(path, chosen.schema_statements())
        return cls(database, chosen, clock=clock, id_factory=id_factory)

    @property
    def database(self) -> Database:
        """Return the underlying database (for inspection and tests)."""
        return self._db

    def _now(self) -> datetime:
        """Return the injected clock's time, which must be timezone-aware."""
        moment = self._clock()
        if moment.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return moment

    def add_memory(
        self, content: str, source: str, parent_ids: Sequence[str] = ()
    ) -> MemoryRecord:
        """Store a new memory and record version 1 in the ledger.

        Args:
            content: the memory text (non-blank).
            source: where it came from, e.g. ``"user"`` or ``"tool:crm"``.
            parent_ids: ``memory_id`` values this memory derives from, in order.
                They must exist and must not repeat.

        Raises:
            ValueError: invalid arguments.
            MemoryNotFoundError: a parent id is unknown (nothing is written).
        """
        _require_text("content", content)
        _require_text("source", source)
        parents = tuple(parent_ids)
        if len(set(parents)) != len(parents):
            raise ValueError("parent_ids must not contain duplicates")

        with self._db.transaction() as conn:
            for parent_id in parents:
                if not self._ledger.memory_exists(conn, parent_id):
                    raise MemoryNotFoundError(f"unknown parent memory {parent_id!r}")
            memory_id = self._new_id()
            version_id = self._new_id()
            now = self._now()
            self._ledger.create_memory(conn, memory_id, now)
            record = self._ledger.append_version(
                conn,
                memory_id=memory_id,
                version_id=version_id,
                version_number=1,
                content=content,
                content_hash=content_hash(content),
                source=source,
                parent_ids=parents,
                created_at=now,
            )
            self._ledger.set_current_version(conn, memory_id, version_id)
            self._store.put(conn, memory_id, content)
            self._ledger.record_event(
                conn,
                event_id=self._new_id(),
                event_type=EVENT_MEMORY_ADDED,
                created_at=now,
                memory_id=memory_id,
                version_id=version_id,
                details={
                    "version_number": 1,
                    "source": source,
                    "parent_ids": list(parents),
                    "content_hash": record.content_hash,
                },
            )
        return record

    def get_memory(self, query: str) -> list[MemoryRecord]:
        """Return the latest, verified version of every memory matching ``query``.

        Candidates are the union of the store's matches and the ledger's own
        matches (same literal, ASCII case-insensitive rule).  Only memories
        whose integrity is ``VALID`` are returned, each at its latest version.
        ``TAMPERED``, ``MISSING`` and untracked store items are excluded and
        each exclusion is recorded as an audit event.  The read itself, with
        the exact ids and versions returned, is recorded too.

        A normal empty search returns ``[]``.  A database or store failure
        raises (:class:`IntegrityError` or ``StorageError``) and rolls the whole
        call back; it never degrades into an empty result.

        Raises:
            ValueError: ``query`` is blank.
            IntegrityError: verification could not be completed.
            StorageError: the database failed.
        """
        _require_text("query", query)
        with self._db.transaction() as conn:
            read_id = self._new_id()
            now = self._now()
            from_ledger = self._ledger.search_current(conn, query)
            from_store = self._store.search(conn, query)
            candidates = list(dict.fromkeys([*from_ledger, *from_store]))
            tracked = self._ledger.order_tracked(conn, candidates)
            tracked_set = set(tracked)
            untracked = [i for i in candidates if i not in tracked_set]

            returned: list[MemoryRecord] = []
            for memory_id in tracked:
                result, stored = self._monitor.check_with_content(conn, memory_id)
                version = self._ledger.get_current_version(conn, memory_id)
                if result.status != "VALID" or stored is None:
                    self._ledger.record_event(
                        conn,
                        event_id=self._new_id(),
                        event_type=EVENT_READ_EXCLUDED,
                        created_at=now,
                        memory_id=memory_id,
                        version_id=version.version_id,
                        read_id=read_id,
                        details={
                            "status": result.status,
                            "expected_hash": result.expected_hash,
                            "actual_hash": result.actual_hash,
                            "query": query,
                        },
                    )
                    continue
                returned.append(
                    MemoryRecord(
                        memory_id=version.memory_id,
                        version_id=version.version_id,
                        version_number=version.version_number,
                        content=stored,
                        source=version.source,
                        parent_ids=version.parent_ids,
                        created_at=version.created_at,
                        content_hash=version.content_hash,
                    )
                )
            for untracked_id in untracked:
                self._ledger.record_event(
                    conn,
                    event_id=self._new_id(),
                    event_type=EVENT_READ_EXCLUDED,
                    created_at=now,
                    read_id=read_id,
                    details={
                        "status": "UNTRACKED",
                        "untracked_id": untracked_id,
                        "query": query,
                    },
                )

            for position, record in enumerate(returned):
                self._ledger.record_read(
                    conn,
                    read_id=read_id,
                    query=query,
                    position=position,
                    memory_id=record.memory_id,
                    version_id=record.version_id,
                    created_at=now,
                )
            self._ledger.record_event(
                conn,
                event_id=self._new_id(),
                event_type=EVENT_READ,
                created_at=now,
                read_id=read_id,
                details={
                    "query": query,
                    "returned_memory_ids": [r.memory_id for r in returned],
                    "returned_version_ids": [r.version_id for r in returned],
                    "excluded_count": len(candidates) - len(returned),
                },
            )
        return returned

    def verify_integrity(self, memory_id: str) -> IntegrityResult:
        """Compare the stored content with the latest ledger version.

        A ``TAMPERED`` or ``MISSING`` outcome is recorded as an audit event.

        Raises:
            MemoryNotFoundError: ``memory_id`` is not tracked.
            IntegrityError: verification could not be completed.
        """
        with self._db.transaction() as conn:
            result = self._monitor.check(conn, memory_id)
            if result.status != "VALID":
                version = self._ledger.get_current_version(conn, memory_id)
                self._ledger.record_event(
                    conn,
                    event_id=self._new_id(),
                    event_type=EVENT_INTEGRITY_FAILED,
                    created_at=self._now(),
                    memory_id=memory_id,
                    version_id=version.version_id,
                    details={
                        "status": result.status,
                        "expected_hash": result.expected_hash,
                        "actual_hash": result.actual_hash,
                    },
                )
        return result

    def update_memory(self, memory_id: str, content: str, source: str) -> MemoryRecord:
        """Append a new version of ``memory_id`` and make it current.

        ``memory_id`` stays the same, ``version_id`` is new, ``version_number``
        increases by 1 and ``parent_ids`` are copied unchanged from the previous
        version.  Earlier versions are never modified.

        The update is refused (and the refusal is recorded) if the stored
        content currently fails verification: overwriting it would destroy the
        evidence and launder the modification into a "valid" new version.

        Raises:
            ValueError: invalid arguments.
            MemoryNotFoundError: ``memory_id`` is not tracked.
            IntegrityError: the current memory is TAMPERED or MISSING, or
                verification could not be completed.
        """
        _require_text("content", content)
        _require_text("source", source)
        refused: IntegrityResult | None = None
        record: MemoryRecord | None = None
        with self._db.transaction() as conn:
            result = self._monitor.check(conn, memory_id)
            previous = self._ledger.get_current_version(conn, memory_id)
            now = self._now()
            if result.status != "VALID":
                refused = result
                self._ledger.record_event(
                    conn,
                    event_id=self._new_id(),
                    event_type=EVENT_UPDATE_REFUSED,
                    created_at=now,
                    memory_id=memory_id,
                    version_id=previous.version_id,
                    details={
                        "status": result.status,
                        "expected_hash": result.expected_hash,
                        "actual_hash": result.actual_hash,
                    },
                )
            else:
                version_id = self._new_id()
                record = self._ledger.append_version(
                    conn,
                    memory_id=memory_id,
                    version_id=version_id,
                    version_number=previous.version_number + 1,
                    content=content,
                    content_hash=content_hash(content),
                    source=source,
                    parent_ids=previous.parent_ids,
                    created_at=now,
                )
                self._ledger.set_current_version(conn, memory_id, version_id)
                self._store.put(conn, memory_id, content)
                self._ledger.record_event(
                    conn,
                    event_id=self._new_id(),
                    event_type=EVENT_MEMORY_UPDATED,
                    created_at=now,
                    memory_id=memory_id,
                    version_id=version_id,
                    details={
                        "version_number": record.version_number,
                        "previous_version_id": previous.version_id,
                        "source": source,
                        "content_hash": record.content_hash,
                    },
                )
        if refused is not None:
            # Raised after the transaction committed, so the refusal stays on record.
            raise IntegrityError(
                f"update refused: memory {memory_id!r} is {refused.status} "
                f"({refused.message})"
            )
        assert record is not None
        return record

    def list_versions(self, memory_id: str) -> list[MemoryRecord]:
        """Return the full immutable version history, oldest first."""
        with self._db.transaction() as conn:
            return self._ledger.list_versions(conn, memory_id)

    def list_audit_events(self, event_type: str | None = None) -> list[AuditEvent]:
        """Return audit events in insertion order, optionally of one type."""
        with self._db.transaction() as conn:
            return self._ledger.list_events(conn, event_type)