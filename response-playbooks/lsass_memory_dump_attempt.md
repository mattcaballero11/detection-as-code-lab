# Response Playbook: LSASS Memory Dump Attempt

## Detection Intent
Identify command-line patterns consistent with LSASS process dumping for credential theft.

## ATT&CK Mapping
- T1003.001 — OS Credential Dumping: LSASS Memory

## Initial Triage
1. Confirm process name, command line, parent process, and user context.
2. Identify whether a dump file was created and where it was written.
3. Check whether the activity came from approved IR tooling.
4. Review recent logons, privilege changes, and suspicious network connections from the host.

## False Positive Candidates
- Approved memory collection by incident responders.
- Endpoint engineering diagnostics.

## Escalation Criteria
Escalate immediately when dumping is unauthorized, performed by a normal user, executed from suspicious paths, or followed by archive/compression/network transfer activity.
