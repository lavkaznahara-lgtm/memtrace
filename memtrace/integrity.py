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

        The content is read exactly once, so the bytes that were hashed are the
        bytes handed back.  For ``TAMPERED`` and ``MISSING`` the second element
        is ``None``: unverified content is never exposed as trusted.

        Raises:
            MemoryNotFoundError: ``memory_id`` is not tracked by the ledger.
            IntegrityError: verification could not be completed (database or
                store failure) or the ledger itself is inconsistent.
        """
        try:
            version = self._ledger.get_current_version(conn, memory_id)
            if content_hash(version.content) != version.content_hash:
                raise IntegrityError(
                    f"ledger version {version.version_id!r} is internally "
                    "inconsistent: its content does not match its recorded hash"
                )
            item = self._store.get(conn, memory_id)
        except MemTraceError:
            raise
        except Exception as exc:  # fail closed on any database or store failure
            raise IntegrityError(
                f"integrity verification failed for {memory_id!r}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        expected = version.content_hash
        if item is None:
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
        actual = content_hash(item.content)
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
            item.content,
        )