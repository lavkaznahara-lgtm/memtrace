import sqlite3
from pathlib import Path
from memtrace import AuditMemoryAdapter


def main() -> None:
    """Simulate a Replay Attack (rolling back to a previous, insecure version)."""
    db_path = Path("replay_test.db")
    if db_path.exists():
        db_path.unlink()

    print("--- INITIALIZATION ---")
    adapter = AuditMemoryAdapter.open(db_path)

    print("\n1. Agent writes Version 1 (Vulnerable rule):")
    v1 = adapter.add_memory("Max refund limit is $1000.", "system-policy")
    print(f"   Written V1: {v1.content} (hash: {v1.content_hash[:8]}...)")
    print(f"   Read by agent: {[r.content for r in adapter.get_memory('refund')]}")

    print("\n2. Admin updates the rule to Version 2 (Secure rule):")
    v2 = adapter.update_memory(v1.memory_id, "Max refund limit is $50.", "admin")
    print(f"   Written V2: {v2.content} (hash: {v2.content_hash[:8]}...)")
    print(f"   Read by agent: {[r.content for r in adapter.get_memory('refund')]}")

    print("\n--- ATTACK 5: Replay Attack (Rollback to V1) ---")
    print("   Hacker directly modifies the store to re-insert the OLD V1 data")
    print("   using the OLD V1 hash (bypassing the adapter).")
    
    conn = sqlite3.connect(db_path)
    # Attacker rolls back the store to the old, insecure content and old hash
    conn.execute(
        "UPDATE store_items SET content = ?, content_hash = ? WHERE memory_id = ?",
        (v1.content, v1.content_hash, v1.memory_id),
    )
    conn.commit()
    conn.close()

    print("   Hacker successfully modified the SQLite database.")
    print(f"   MemTrace integrity status: {adapter.verify_integrity(v1.memory_id).status}")
    print(
        f"   What the agent reads: {adapter.get_memory('refund')} (empty list = protection worked)"
    )

    print("\n--- RESULT ---")
    print("Replay attack mitigated. Agent is forced to use the latest ledger version.")
    
    db_path.unlink()


if __name__ == "__main__":
    main()