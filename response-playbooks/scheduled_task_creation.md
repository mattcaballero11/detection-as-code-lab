# Response Playbook — Suspicious Scheduled Task Creation

| | |
| :--- | :--- |
| **Detection** | Suspicious Scheduled Task Creation |
| **ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Execution / Persistence |
| **Severity** | Medium–High |

## Detection intent

Flags creation of a scheduled task via `schtasks.exe /create` or PowerShell `Register-ScheduledTask`. Attackers use scheduled tasks to persist across reboots, execute payloads on a trigger (logon, interval, on-start), or run code in an elevated (SYSTEM) context.

## Initial triage

1. **Inspect the action** — what binary or command does the task run, and from what path? A script in `%TEMP%` or `%APPDATA%` is a red flag.
2. **Examine the task name** — is it random, or masquerading as a legitimate Windows/vendor task to blend in?
3. **Check the run context** — does it run as SYSTEM or with highest privileges?
4. **Identify who created it** and the parent process of `schtasks.exe`.

## Enrichment fields

- The task's **action/target binary** path and reputation/hash.
- `AccountName` / `DeviceName` and whether task creation is normal for this account.
- Parent process of the creation event.
- Whether the task name imitates a known-good task.

## False positives

- Software installers, patch management, and backup jobs create scheduled tasks routinely.
- Administrators creating maintenance tasks.
- Baseline known-good task names/paths and tune those out.

## Escalation criteria

Escalate if **any** apply:

- the task runs a script from a user-writable path (`Temp`, `AppData`) or an encoded command,
- it runs as **SYSTEM** / highest privileges,
- the name masquerades as a legitimate task,
- creation closely follows other suspicious activity on the host.

## Containment

1. **Disable or delete** the malicious task.
2. **Capture** the task XML and the referenced action for analysis.
3. **Investigate** the referenced binary/script (hash, origin).
4. **Hunt** for the same task name/action across other hosts.
5. **Remove** the persistence and any staged payload; reset credentials if warranted.
