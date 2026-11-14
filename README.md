# MemTrace

An independent **memory auditing layer for AI agents**. It wraps the memory store
an agent already uses, records an immutable provenance ledger of every write and
read, and refuses to hand back memories whose stored content no longer matches
what the ledger recorded.

This is the **Day 1 MVP**: interception, an immutable version ledger and integrity
checks. Graph visualisation, rollback, impact analysis, leave-one-out replay and any
UI are *not* built yet (only interfaces are prepared, see "Day 2").

## Security boundary (read this first)

Day 1 detects **accidental corruption and unauthorized modifications when the
provenance ledger remains intact**. The mock store and the ledger may share one
SQLite database, but this does **NOT** protect against an attacker who modifies
both. **Do not claim cryptographic tamper-proof protection.**

Concretely:

- The ledger is the trust anchor. Expected hashes come only from the latest ledger
  version; the store's own `content_hash` column is never trusted.
- The append-only triggers on the ledger tables stop accidental and naive changes.
  Anyone who can write to the SQLite file can drop them, rewrite the ledger and the
  store consistently, and go undetected. A test documents exactly this
  (`test_security_boundary_an_attacker_who_rewrites_both_is_not_detected`).
- There are no signatures, no hash chain and no external anchoring. Those are
  prerequisites for any tamper-evidence claim and are out of scope for Day 1.

## Install and run

Requires Python 3.11+ and nothing else at runtime (standard library only).

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"              # or: pip install -r requirements.txt && pip install -e .

pytest                               # 52 tests
mypy --strict memtrace tests examples
python examples/basic_usage.py
```

## Usage

```python
from memtrace import AuditMemoryAdapter

adapter = AuditMemoryAdapter.open("memtrace.db")      # file-backed SQLite

policy = adapter.add_memory("Refunds above $100 need approval.", source="policy-doc")
note = adapter.add_memory("Customer asked about a refund.", "chat",
                          parent_ids=(policy.memory_id,))

adapter.get_memory("refund")                # only latest versions that verify as VALID
adapter.verify_integrity(policy.memory_id)  # IntegrityResult(status="VALID" | "TAMPERED" | "MISSING")
adapter.update_memory(policy.memory_id, "Refunds above $200 need approval.", "policy-doc")
```

`AuditMemoryAdapter(database, store)` wraps any object implementing the
`MemoryStore` protocol (`put`, `get`, `search`, `schema_statements`). `SimpleVectorStore`
is a mock SQLite store with deterministic lexical search (SQL `LIKE`); replace its
`search` with embeddings later without touching the adapter.

## Behavioural contracts

- **`add_memory`** creates a stable `memory_id`, a `version_id`, `version_number` 1,
  and records the ordered `parent_ids` (they must exist and not repeat).
- **`update_memory`** keeps `memory_id`, creates a new `version_id`, increments
  `version_number` by exactly 1 and copies `parent_ids` unchanged from the previous
  version. Earlier versions are never modified (enforced by triggers and tested).
- **`get_memory`** returns only the **latest** version of each matching memory and
  only if its integrity is `VALID`. `TAMPERED`, `MISSING` and untracked store items
  are excluded and each exclusion becomes an audit event. Every read is recorded in
  `memory_reads` with the exact returned memory and version ids. A normal empty
  search returns `[]`; a system error raises and never turns into an empty list.
- **`verify_integrity`** hashes the content the store holds now and compares it with
  the hash recorded in the **latest ledger version referenced by the logical memory**.
  Missing store item: `MISSING`. Different hash: `TAMPERED`. The result never
  contains the stored content.

### Errors

| Exception | Raised when |
|---|---|
| `MemoryNotFoundError` | unknown `memory_id` or unknown parent id |
| `IntegrityError` | verification could not be completed (database or store failure), the ledger itself is inconsistent, or an update is refused because the current memory is `TAMPERED`/`MISSING` |
| `StorageError` | the SQLite database failed (including `sqlite3.Error` raised inside a transaction) |
| `ValueError` | blank content, source or query; duplicate parents; in-memory database path |

All inherit from `MemTraceError`.

## Ledger schema

`memories` (one row per logical memory, `current_version_id` points at its latest
version), `memory_versions` (immutable history: content, SHA-256, source, ordered
parent ids as JSON, timestamps), `audit_events` and `memory_reads` (both
append-only). Foreign keys and indexes are defined in `memtrace/ledger.py`. The mock
store adds one table, `store_items`.

SQLite handling: every operation uses `Database.transaction()`, which opens its own
connection, enables foreign keys on it (and verifies that), runs `BEGIN IMMEDIATE`,
commits on success, rolls back on failure and always closes the connection. WAL mode
is enabled once, during initialisation. In-memory databases are rejected because
each connection would see a different database.

## Design decisions worth knowing

- **Candidates for a read are the union of the store's matches and the ledger's own
  matches.** Otherwise a deleted or rewritten memory would silently disappear from
  results instead of being reported. This assumes the store's search rule and the
  ledger's lexical rule agree, which holds for the mock store; for a real vector
  store the shadow search is a Day 2 question.
- **Untracked store items** (present in the store, unknown to the ledger, e.g. injected
  directly) are never returned and are audited as `UNTRACKED`.
- **`update_memory` refuses to build on a failing memory**, so an update cannot launder
  a modification into a "valid" new version or overwrite the evidence. The refusal is
  committed as an `UPDATE_REFUSED` event.
- **A read is a write transaction** (it records events), so concurrent readers are
  serialised.
- Parent ids are stored as an ordered JSON list in `memory_versions`, so SQLite cannot
  enforce them as foreign keys; the adapter validates them on write.
- Search is literal (`%`, `_` are escaped) and ASCII case-insensitive (SQLite `LIKE`).
- The store write and the ledger write are atomic only because they share one database.
  A store living elsewhere needs its own compensation (not in Day 1).

## Day 2 extension points (interfaces only, not implemented)

`memtrace/models.py` declares `ProvenanceLinkReader`, `ProvenanceGraphBuilder`
(generic over the graph type, so Day 2 can bind it to a NetworkX `DiGraph` without a
Day 1 dependency), `RollbackEngine`, `ImpactAnalyzer` and `ReplayEngine`
(leave-one-out replay). Nothing implements them yet.

## Verification

Run during development: `pytest` (52 passed) and `mypy --strict memtrace tests
examples` (no issues) on Python 3.12.3, SQLite 3.45.1, pytest 9.2.0, mypy 2.4.1.
Mypy targets Python 3.11 (`python_version` in `pyproject.toml`), but the tests were
**not executed on Python 3.11**.

The tests were also checked by deliberately breaking the source in 15 ways (for
example never reporting `TAMPERED`, exposing tampered content, dropping the shadow
search, dropping parent ids on update, removing the append-only trigger, never
closing or committing a connection); every breakage made at least one test fail.

## Limitations

- Not tamper-proof (see the security boundary above).
- Lexical search only; no embeddings.
- Single-process, file-backed SQLite; concurrency is serialised, not stress-tested.
- Only the latest content of a memory is verifiable in the store; historical versions
  live in the ledger.
- The prescribed project structure has no `LICENSE` file; add one before publishing.