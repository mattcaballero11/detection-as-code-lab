# Response Playbook — WMI Process Execution

| | |
| :--- | :--- |
| **Detection** | WMI Process Execution |
| **ATT&CK** | [T1047](https://attack.mitre.org/techniques/T1047/) — Windows Management Instrumentation |
| **Tactic** | Execution |
| **Severity** | Medium–High |

## Detection intent

Flags process creation via WMI — `wmic process call create`, or `Win32_Process.Create` invoked through PowerShell. Attackers use WMI for execution and lateral movement because the spawned process's parent is `WmiPrvSE.exe`, which breaks naive parent/child process-tree detections and can hide the true origin.

## Initial triage

1. **Identify what WMI spawned** — the full command line of the child process.
2. **Determine local vs remote** — was this triggered from another host? Remote WMI is a lateral-movement signal.
3. **Confirm the parent is `WmiPrvSE.exe`** — the tell-tale of WMI-based spawning.
4. **Establish the acting account** and target host.

## Enrichment fields

- The spawned binary/command **reputation and hash**.
- If remote, the **source host** — correlate with authentication logs.
- `AccountName` / `DeviceName`.
- Logon events (network logon, type 3) around the execution.

## False positives

- Legitimate remote administration and management tools use WMI (SCCM, monitoring/inventory agents).
- Some software uses `Win32_Process` internally.
- Baseline known management sources and tune those out.

## Escalation criteria

Escalate if **any** apply:

- WMI spawns encoded PowerShell or a script from a user-writable path,
- the invocation is **remote from an unexpected source host**,
- it targets a sensitive host,
- it's chained with other lateral-movement indicators (admin-share access, service creation).

## Containment

1. **Isolate** the affected host.
2. **Capture** the spawned command and correlate the **source host and credentials** — remote WMI usually means an already-compromised account.
3. **Investigate the origin host** as likely patient-zero for this movement.
4. **Hunt** for the same WMI-spawn pattern across the environment.
5. **Reset credentials** for the involved account.
