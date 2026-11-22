"""
Real-world scenario: AI Agent Memory Protection.

Simulates an AI customer support agent whose memory is tampered with
directly in the underlying SQLite database, bypassing the application layer.
"""
import sys
import sqlite3
from pathlib import Path
from memtrace import AuditMemoryAdapter

# Fix Windows console encoding to display emojis correctly
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')


def run_simulation() -> None:
    db_path = Path("agent_memory_demo.db")
    if db_path.exists():
        db_path.unlink()

    print("=" * 65)
    print("🚀 STARTING REAL-WORLD TAMPERING SIMULATION")
    print("=" * 65 + "\n")

    # 1. Initialize the agent's memory adapter
    print("🤖 [Agent] Initializing memory adapter...")
    agent_memory = AuditMemoryAdapter.open(db_path)

    # 2. Agent stores a critical policy rule
    rule = "Max refund allowed: $100. Requires manager approval."
    print(f"🤖 [Agent] Saving critical rule: '{rule}'")
    record = agent_memory.add_memory(rule, "system_policy")
    status = agent_memory.verify_integrity(record.memory_id)
    print(f"✅ [MemTrace] Rule saved. Integrity status: {status.status}\n")

    # 3. Agent reads the rule to process a refund
    print("🤖 [Agent] Reading rule to process a refund...")
    found = agent_memory.get_memory("Max refund")
    print(f"🤖 [Agent] Found rule: '{found[0].content}'\n")

    # 4. ATTACK: Attacker tampers directly with the SQLite store, bypassing the application
    print("🚨 [Attacker] Bypassing the application, tampering directly in the SQLite DB...")
    malicious_rule = "Max refund allowed: $10000. No approval needed."
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE store_items SET content = ? WHERE memory_id = ?",
        (malicious_rule, record.memory_id),
    )
    conn.commit()
    conn.close()
    print(f"🚨 [Attacker] Store content changed to: '{malicious_rule}'\n")

    # 5. Agent attempts to read the rule again
    print("🤖 [Agent] Trying to read rule again...")
    try:
        found_after_hack = agent_memory.get_memory("Max refund")
        if len(found_after_hack) == 0:
            print("🛡️ [MemTrace] BLOCKED! Memory was tampered with and excluded from results.")
        else:
            print(f"💀 [FAIL] Agent read the corrupted rule: '{found_after_hack[0].content}'")
    except Exception as e:
        print(f"🛡️ [MemTrace] BLOCKED! Raised error: {e}\n")

    # 6. Final integrity verification
    status = agent_memory.verify_integrity(record.memory_id)
    print(f"\n🔍 [MemTrace] Final integrity check status: {status.status}")
    if status.status == "TAMPERED":
        print("✅ SUCCESS: MemTrace successfully detected the tampering!")
        print("⚠️  NOTE: The underlying store remains corrupted. Manual recovery is required.")
    else:
        print("❌ FAILED: MemTrace did not detect the tampering.")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    run_simulation()
