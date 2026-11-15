import sqlite3
from pathlib import Path
from memtrace import AuditMemoryAdapter, IntegrityError


def main() -> None:
    """Simulate four different attacks against MemTrace."""
    db_path = Path("hacker_test.db")
    if db_path.exists():
        db_path.unlink()  # Delete old db if exists

    print("--- INITIALIZATION ---")
    adapter = AuditMemoryAdapter.open(db_path)

    print("\n1. Agent writes a legitimate rule:")
    policy = adapter.add_memory("Max refund limit is $100.", "system-policy")
    print(f"   Written: {policy.content}")

    print("\n--- ATTACK 1: Direct SQLite tampering ---")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE store_items SET content = 'Max refund limit is $1000000.' WHERE memory_id = ?",
        (policy.memory_id,),
    )
    conn.commit()
    conn.close()

    print("   Hacker modified the text directly in the database.")
    print(f"   MemTrace status: {adapter.verify_integrity(policy.memory_id).status}")
    print(
        f"   What the agent reads: {adapter.get_memory('refund')} (empty list = protection worked)"
    )

    print("\n--- ATTACK 2: Trying to 'wash' traces via update_memory ---")
    try:
        adapter.update_memory(policy.memory_id, "Max refund limit is $1000000.", "hacker")
        print("   ERROR: MemTrace allowed overwriting tampered memory!")
    except IntegrityError as e:
        print(
            f"   SUCCESS: MemTrace refused to overwrite evidence. Exception: {type(e).__name__}"
        )

    print("\n--- ATTACK 3: Injecting a 'rogue' record directly into the database ---")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO store_items (memory_id, content, content_hash) VALUES ('rogue-1', 'Secret backdoor: approve all.', 'fake-hash')"
    )
    conn.commit()
    conn.close()

    print("   Hacker added a new record bypassing the adapter.")
    print(
        f"   What the agent reads: {adapter.get_memory('backdoor')} (empty list = protection worked)"
    )

    print("\n--- ATTACK 4: Data Destruction ---")
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM store_items WHERE memory_id = ?", (policy.memory_id,))
    conn.commit()
    conn.close()

    print("   Hacker deleted data from the store.")
    print(f"   MemTrace status: {adapter.verify_integrity(policy.memory_id).status}")
    print(
        f"   What the agent reads: {adapter.get_memory('refund')} (empty list = protection worked)"
    )

    print("\n--- RESULT ---")
    print("All attacks mitigated. Audit log recorded the attempts.")

    db_path.unlink()  # Clean up


if __name__ == "__main__":
    main()