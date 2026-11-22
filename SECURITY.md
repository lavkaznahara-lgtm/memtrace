# Security Policy

## Supported Versions
Currently, only the `main` branch (Day 1 MVP) is actively maintained and receives security updates.

## Reporting a Vulnerability
MemTrace is designed to detect tampering, but the tool itself may have undiscovered vulnerabilities. 

If you discover a security issue, please **do not** open a public GitHub issue. 
Instead, please email the maintainer directly at: **lavkaznahara@gmail.com**.

I will acknowledge your report within 48 hours and provide a timeline for investigation and a fix.

## Threat Model
Please read the "Security boundary" section in the [README](README.md) carefully before reporting. 

**What MemTrace protects against (Day 1):**
- Direct, unauthorized modifications to the underlying SQLite store (e.g., an attacker bypassing the application to edit the database file).
- Accidental data corruption.

**What MemTrace does NOT protect against (yet):**
- It does **not** prevent writes to the database.
- It does **not** detect "poisoned" content written through the legitimate `add_memory` API (e.g., if a compromised AI agent itself writes malicious data, it will be ledgered as VALID).
- It does **not** provide cryptographic tamper-evidence (no hash chains or external anchoring in Day 1).

MemTrace's primary defense is detection: it verifies store content against the provenance ledger and refuses to return corrupted memories to the agent.
