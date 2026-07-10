# Response Playbook: Suspicious PowerShell Encoded Command

## Detection Intent
Identify PowerShell execution using encoded command switches that may indicate obfuscated script execution.

## ATT&CK Mapping
- T1059.001 — Command and Scripting Interpreter: PowerShell

## Initial Triage
1. Decode the Base64 payload when safe and appropriate.
2. Review parent process and process tree.
3. Confirm user, host, and execution timestamp.
4. Check whether the account normally runs automation scripts.
5. Review network connections, file writes, and child processes around the same time.

## False Positive Candidates
- Endpoint management scripts.
- Software deployment tools.
- Approved internal administration scripts.

## Escalation Criteria
Escalate if execution is spawned by Office, browser, archive tools, unknown binaries, temp paths, or if the decoded command downloads payloads, disables security controls, or accesses credentials.
