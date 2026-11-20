"""MemTrace: an independent memory auditing layer for AI agents (Day 1 MVP)."""

from memtrace.adapter import AuditMemoryAdapter
from memtrace.integrity import IntegrityMonitor
from memtrace.ledger import LEDGER_SCHEMA, Database, Ledger
from memtrace.models import (
    AuditEvent,
    IntegrityError,
    IntegrityResult,
    MemoryNotFoundError,
    MemoryRecord,
    MemTraceError,
    StorageError,
)
from memtrace.store import MemoryStore, SimpleLexicalStore, StoredItem

__version__ = "0.1.0"

__all__ = [
    "LEDGER_SCHEMA",
    "AuditEvent",
    "AuditMemoryAdapter",
    "Database",
    "IntegrityError",
    "IntegrityMonitor",
    "IntegrityResult",
    "Ledger",
    "MemTraceError",
    "MemoryNotFoundError",
    "MemoryRecord",
    "MemoryStore",
    "SimpleLexicalStore",
    "StorageError",
    "StoredItem",
    "__version__",
]