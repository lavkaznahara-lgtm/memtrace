"""Domain models, exceptions and Day 2 extension points for MemTrace.

Everything here is pure data or typing: no I/O and no SQLite.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, TypeVar

IntegrityStatus = Literal["VALID", "TAMPERED", "MISSING"]


class MemTraceError(Exception):
    """Base class for every error raised by MemTrace."""


class IntegrityError(MemTraceError):
    """Integrity could not be established, or the ledger itself is inconsistent.

    Raised for system-level problems (database errors during verification, an
    inconsistent ledger) and when an update is refused because the current
    memory fails verification.  A memory whose stored content merely differs
    from the ledger is *not* an error: it is reported as ``TAMPERED`` or
    ``MISSING`` in an :class:`IntegrityResult`.
    """


class MemoryNotFoundError(MemTraceError):
    """The requested logical memory does not exist in the ledger."""


class StorageError(MemTraceError):
    """The underlying SQLite database failed or is unusable."""


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    """One immutable version of a logical memory.

    ``memory_id`` is stable across updates; ``version_id`` changes with every
    update and ``version_number`` starts at 1 and increases by exactly 1.
    """

    memory_id: str
    version_id: str
    version_number: int
    content: str
    source: str
    parent_ids: tuple[str, ...]
    created_at: datetime
    content_hash: str


@dataclass(frozen=True, slots=True)
class IntegrityResult:
    """Outcome of verifying the stored content against the ledger.

    ``expected_hash`` comes from the ledger version; ``actual_hash`` is the hash
    of what the store holds right now (``None`` when the item is missing).  The
    result never carries the stored content itself.
    """

    memory_id: str
    status: IntegrityStatus
    expected_hash: str | None
    actual_hash: str | None
    message: str


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A row of the append-only ``audit_events`` table."""

    seq: int
    event_id: str
    event_type: str
    memory_id: str | None
    version_id: str | None
    read_id: str | None
    details: Mapping[str, object]
    created_at: datetime


def content_hash(content: str) -> str:
    """Return the lowercase SHA-256 hex digest of ``content`` (UTF-8)."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def escape_like(text: str) -> str:
    """Escape ``%``, ``_`` and the escape character itself for SQL ``LIKE``.

    Use together with ``ESCAPE '\\'`` so user queries are matched literally.
    """
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Day 2 extension points: interfaces only, deliberately NOT implemented.
# ---------------------------------------------------------------------------

GraphT_co = TypeVar("GraphT_co", covariant=True)
ReplayT_co = TypeVar("ReplayT_co", covariant=True)


class ProvenanceLinkReader(Protocol):
    """Reads provenance links (``parent_ids``) between logical memories."""

    def parents_of(self, memory_id: str) -> tuple[str, ...]:
        """Return the parent memory ids recorded for ``memory_id``."""
        ...

    def children_of(self, memory_id: str) -> tuple[str, ...]:
        """Return the ids of memories that list ``memory_id`` as a parent."""
        ...


class ProvenanceGraphBuilder(Protocol[GraphT_co]):
    """Builds a provenance graph (Day 2 binds ``GraphT`` to a NetworkX DiGraph)."""

    def build_graph(self, memory_ids: Sequence[str] | None = None) -> GraphT_co:
        """Build the graph for ``memory_ids`` (all memories when ``None``)."""
        ...


class RollbackEngine(Protocol):
    """Restores a memory to an earlier ledger version."""

    def rollback(self, memory_id: str, to_version_number: int) -> MemoryRecord:
        """Make ``to_version_number`` current again and return the new record."""
        ...


class ImpactAnalyzer(Protocol):
    """Answers "what is affected if this memory is bad?"."""

    def impact_of(self, memory_id: str) -> Sequence[str]:
        """Return ids of descendants and of reads that returned ``memory_id``."""
        ...


class ReplayEngine(Protocol[ReplayT_co]):
    """Leave-one-out replay of a recorded read (Day 2)."""

    def replay_without(
        self, read_id: str, excluded_memory_ids: Sequence[str]
    ) -> ReplayT_co:
        """Re-run the step behind ``read_id`` with some memories removed."""
        ...