# Response Playbook — Windows Defender Disabled via Command Line

| | |
| :--- | :--- |
| **Detection** | Windows Defender Disabled via Command Line |
| **ATT&CK** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools |
| **Tactic** | Defense Evasion |
| **Severity** | High |

## Detection intent

Flags command-line tampering that weakens or disables Microsoft Defender before payload execution — for example `Set-MpPreference -DisableRealtimeMonitoring $true`, adding a Defender **exclusion path**, stopping the `WinDefend` service, or setting the `DisableAntiSpyware` registry value. Disabling AV is a classic precursor to running malware.

## Initial triage

1. **Identify the method** — real-time monitoring off, exclusion added, service stopped, or registry modification?
2. **If an exclusion was added, capture the excluded path** — attackers exclude a folder, then execute from it. This path is a high-value hunt lead.
3. **Confirm privilege** — these changes require admin; how did the actor obtain it?
4. **Identify the parent process** and the acting account.

## Enrichment fields

- `AccountName` / `DeviceName` and whether this change is expected.
- Parent process of the tampering command.
- **Correlate with subsequent execution** in the excluded path or right after protection was disabled.
- Timeline of events around the change.

## False positives

- Admins/EDR deployments occasionally adjust Defender legitimately (e.g. when installing third-party AV).
- GPO- or MDM-driven configuration changes.
- Tune out sanctioned change windows and management tooling.

## Escalation criteria

Escalate if **any** apply:

- an exclusion was added **and** a file subsequently executed from that path,
- real-time protection was disabled outside an approved change window,
- it occurred on a sensitive host,
- it's chained with other TTPs (persistence, credential access).

## Containment

1. **Re-enable** Defender / remove the malicious exclusion.
2. **Isolate** the host if malicious execution followed the change.
3. **Hunt** for whatever ran in the exclusion/disabled window.
4. **Investigate** how the actor gained the required privilege.
5. **Reset credentials** for the involved account if compromise is suspected.
