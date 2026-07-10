# Response Playbook — Suspicious PowerShell Encoded Command

| | |
| :--- | :--- |
| **Detection** | Suspicious PowerShell Encoded Command |
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Severity** | High |

## Detection intent

Flags PowerShell executed with an encoded-command parameter (`-enc`, `-encodedcommand`, `-e`, `/enc`, `/encodedcommand`). Base64-encoded commands are a common way to obscure malicious payloads from casual inspection and simple string-based controls.

## Initial triage

1. **Decode the command.** Base64-decode the encoded string to reveal the actual PowerShell that ran. This is the single most informative step.
2. **Assess the decoded intent.** Look for download cradles (`Net.WebClient`, `Invoke-WebRequest`, `iwr`, `DownloadString`), in-memory execution (`IEX`, `Invoke-Expression`), or encoded/compressed nested payloads.
3. **Establish context.** Who ran it, on which host, and what was the **parent process**? PowerShell spawned by `winword.exe`, `excel.exe`, or `outlook.exe` is far more suspicious than one launched from an admin's console.

## Enrichment fields

- `AccountName` — is this a normal user for this host, and is the activity within their working hours?
- `DeviceName` — is this a server, a developer workstation, or a standard endpoint?
- `InitiatingProcessFileName` (parent) — Office app or browser child = elevate priority.
- Any network destination from the decoded command — reputation-check the domain/IP.

## False positives

- Administrators and automation frameworks (SCCM, some installers) occasionally use encoded commands legitimately.
- Baseline known-good automation by host/account and tune those out rather than lowering the rule's fidelity.

## Escalation criteria

Escalate to incident response if **any** of the following hold:

- the decoded command contacts an external host or downloads a payload,
- the parent process is an Office application, browser, or other user-facing app,
- execution occurred on a sensitive host (domain controller, server, privileged workstation),
- the same pattern appears across multiple hosts in a short window (possible campaign).

## Containment

1. **Isolate** the affected host from the network if malicious execution is confirmed.
2. **Preserve** the decoded command, process tree, and relevant logs for investigation.
3. **Reset credentials** for the involved account if credential access or theft is suspected.
4. **Hunt laterally** for the same encoded pattern and any downloaded artifacts across the estate.
5. **Add** any confirmed-malicious domains/IPs/hashes to blocklists and, where useful, to a new detection.
