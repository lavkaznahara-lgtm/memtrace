"""Integrity monitor: compare what the store holds with what the ledger recorded.

The expected hash always comes from the *latest ledger version referenced by
the logical memory record*.  The store's own ``content_hash`` column is never
consulted: whoever can edit a store row can edit that column as well.

Security boundary: this detects accidental corruption and unauthorized changes
made to the store while the ledger stays intact.  It does not defend against an
attacker who rewrites both (see README).
"""

from __future__ import annotations

import sqlite3

from memtrace.ledger import Ledger
from memtrace.models import (
    IntegrityError,
    IntegrityResult,
    MemTraceError,
    content_hash,
)
from memtrace.store import MemoryStore


class IntegrityMonitor:
    """Verifies stored content against the immutable ledger."""

    def __init__(self, ledger: Ledger, store: MemoryStore) -> None:
        """Bind the monitor to a ledger and the store being audited."""
        self._ledger = ledger
        self._store = store

    def check(self, conn: sqlite3.Connection, memory_id: str) -> IntegrityResult:
        """Return the integrity status of ``memory_id`` (never its content)."""
        result, _ = self.check_with_content(conn, memory_id)
        return result

    def check_with_content(
        self, conn: sqlite3.Connection, memory_id: str
    ) -> tuple[IntegrityResult, str | None]:
        """Verify ``memory_id`` and return the stored content only if it is VALID.

        The store item's ``memory_id`` is checked before its content, and its
        ``content`` is read exactly once, so the bytes that were hashed are the
        bytes handed back (no split-view).  For ``TAMPERED`` and ``MISSING`` the
        second element is ``None``: unverified content is never exposed as
        trusted.

        Raises:
            MemoryNotFoundError: ``memory_id`` is not tracked by the ledger.
            IntegrityError: verification could not be completed (database or
                store failure, including any exception raised while reading the
                store item), the store returned a different ``memory_id`` or
                content of the wrong type, or the ledger itself is inconsistent.
        """
        stored: str | None = None
        actual: str | None = None
        try:
            # Raises IntegrityError if the ledger version is internally inconsistent.
            version = self._ledger.get_current_version(conn, memory_id)
            item = self._store.get(conn, memory_id)
            if item is not None:
                # RT-007: the store must answer for the memory we asked about.
                # Read the id once and require an exact ``str``.  ``str.__ne__``
                # ignores comparison overrides on either operand; anything other
                # than ``False`` (including ``NotImplemented``) is a mismatch.
                returned_id = item.memory_id
                if type(returned_id) is not str:
                    raise IntegrityError("store returned invalid memory_id type")
                if str.__ne__(returned_id, memory_id) is not False:
                    raise IntegrityError(
                        f"store returned mismatched memory_id: expected "
                        f"{memory_id!r}, got {returned_id!r}"
                    )
                # RT-008: read ``content`` exactly once.  The local below is the
                # only thing that is type-checked, hashed and returned, so the
                # bytes that were verified are the bytes handed to the caller.
                content = item.content
                if type(content) is not str:
                    raise IntegrityError("store returned invalid content type")
                actual = content_hash(content)
                stored = content
        except MemTraceError:
            raise
        except Exception as exc:  # fail closed on any database or store failure
            raise IntegrityError(
                f"integrity verification failed for {memory_id!r}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        expected = version.content_hash
        if stored is None or actual is None:
            return (
                IntegrityResult(
                    memory_id=memory_id,
                    status="MISSING",
                    expected_hash=expected,
                    actual_hash=None,
                    message=(
                        f"no stored content for ledger version "
                        f"{version.version_number} ({version.version_id})"
                    ),
                ),
                None,
            )
        if actual != expected:
            return (
                IntegrityResult(
                    memory_id=memory_id,
                    status="TAMPERED",
                    expected_hash=expected,
                    actual_hash=actual,
                    message=(
                        f"stored content does not match ledger version "
                        f"{version.version_number} ({version.version_id})"
                    ),
                ),
                None,
            )
        return (
            IntegrityResult(
                memory_id=memory_id,
                status="VALID",
                expected_hash=expected,
                actual_hash=actual,
                message=(
                    f"stored content matches ledger version "
                    f"{version.version_number} ({version.version_id})"
                ),
            ),
            stored,
        )