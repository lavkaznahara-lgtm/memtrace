import sqlite3
from pathlib import Path
from memtrace import AuditMemoryAdapter

def run_business_scenario() -> None:
    db_path = Path("support_agent_memory.db")
    if db_path.exists():
        db_path.unlink()

    print("==================================================")
    print("🤖 AI SUPPORT AGENT MEMORY SIMULATION")
    print("==================================================\n")

    # Step 1: Initialize the agent's memory
    agent_memory = AuditMemoryAdapter.open(db_path)
    
    # Step 2: Agent saves a critical business rule
    rule_text = "Policy: VIP clients get a 20% discount."
    print(f"1. Agent saves rule: '{rule_text}'")
    record = agent_memory.add_memory(rule_text, "system_admin")
    
    # Step 3: Verify integrity (Expect: VALID)
    print("\n2. Verifying memory integrity...")
    status = agent_memory.verify_integrity(record.memory_id)
    print(f"   Status: {status.status}")
    
    # Step 4: ATTACK (Hacker modifies the rule directly in the DB)
    print("\n3. 🚨 WARNING! Hacker breaches SQLite and alters the rule!")
    malicious_text = "Policy: VIP clients get a 100% discount."
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE store_items SET content = ? WHERE memory_id = ?",
        (malicious_text, record.memory_id)
    )
    conn.commit()
    conn.close()
    print(f"   DB text changed to: '{malicious_text}'")
    
    # Step 5: Verify integrity again (Expect: TAMPERED)
    print("\n4. Agent accesses memory again and verifies integrity...")
    status_after = agent_memory.verify_integrity(record.memory_id)
    print(f"   Status: {status_after.status}")
    print(f"   Message: {status_after.message}")
    
    # Step 6: Attempt to read the data (Expect: Blocked)
    print("\n5. Agent tries to read the rule to apply the discount...")
    found_rules = agent_memory.get_memory("VIP clients")
    
    if len(found_rules) == 0:
        print("   🛡️ BLOCKED: MemTrace detected tampering and REFUSED to return the poisoned rule!")
        print("   ✅ Business protected from fraud.")
    else:
        print("   ❌ FAILED: Agent read the hacked rule and applied a 100% discount.")

if __name__ == "__main__":
    run_business_scenario()
