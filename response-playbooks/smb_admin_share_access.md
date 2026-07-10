# Response Playbook — SMB Admin Share Access

| | |
| :--- | :--- |
| **Detection** | SMB Admin Share Access |
| **ATT&CK** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) — Remote Services: SMB/Windows Admin Shares |
| **Tactic** | Lateral Movement |
| **Severity** | Medium–High |

## Detection intent

Flags access to administrative shares (`C$`, `ADMIN$`, `IPC$`). Attackers use these to move laterally: dropping files to a remote host and executing them (PsExec-style), often after obtaining privileged credentials.

## Initial triage

1. **Identify source and destination hosts** — where did the connection originate, and where did it land?
2. **Which share** was accessed (`C$`, `ADMIN$`, `IPC$`)?
3. **Which account**, and is it privileged? Is admin-share access normal for it?
4. **Look for follow-on activity** — files written to `ADMIN$`, then a **service creation** (event 7045) or remote process execution on the target.

## Enrichment fields

- **Source host** context and whether it's an expected admin origin.
- `AccountName` — normal for this account to touch admin shares?
- Correlate with **network logon (type 3)** events.
- Subsequent service creation or process execution on the destination.

## False positives

- Legitimate admin tooling, backup, deployment, and monitoring access admin shares **routinely**.
- Sysadmins using PsExec or remote management as part of normal operations.
- Baseline known admin source hosts/accounts and tune those out.

## Escalation criteria

Escalate if **any** apply:

- access originates from a **non-admin or unexpected source host**,
- a file is written to `ADMIN$` **and** a service is subsequently created on the target,
- a privileged account is used **off-hours**,
- the same source→destination pattern spreads across many hosts (worm-like movement).

## Containment

1. **Isolate** the affected source and destination hosts.
2. **Identify the credentials** used — treat them as compromised and **reset** them.
3. **Capture** any files written to the admin share.
4. **Hunt** for the same source→destination access pattern across the estate to scope the spread.
5. **Investigate initial access** — how the actor obtained the privileged credentials.
