# Response Playbook — PowerShell Download Cradle

| | |
| :--- | :--- |
| **Detection** | PowerShell Download Cradle |
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — PowerShell · [T1105](https://attack.mitre.org/techniques/T1105/) — Ingress Tool Transfer |
| **Tactic** | Execution / Command and Control |
| **Severity** | High |

## Detection intent

Flags PowerShell that retrieves remote content and runs it in memory — a "download cradle" (e.g. `Net.WebClient.DownloadString`, `Invoke-WebRequest`/`iwr`, `Invoke-RestMethod`, often piped to `IEX`/`Invoke-Expression`). This is a fileless way to pull and execute a next-stage payload without writing it to disk.

## Initial triage

1. **Extract the URL/host** the cradle contacts — this is the most important artifact.
2. **Confirm in-memory execution** — is the download piped to `IEX`/`Invoke-Expression`? Download-and-run is far more serious than a plain download.
3. **Check whether it succeeded** — was a network connection actually established and content returned?
4. **Identify the parent process** — PowerShell spawned by an Office app or browser is a strong compromise signal.

## Enrichment fields

- The destination **domain/IP** — reputation, age, hosting provider, and whether it's a known-bad indicator.
- `AccountName` / `DeviceName` — normal for this user/host, and within working hours?
- Parent process — Office/browser child elevates priority.
- Proxy/DNS logs for the fetch, to confirm the connection and capture the full URL.

## False positives

- Package managers and admin tooling (e.g. Chocolatey) legitimately use download patterns.
- Internal automation pulling from **known-good internal** hosts.
- Baseline trusted internal sources and tune those out rather than lowering rule fidelity.

## Escalation criteria

Escalate to incident response if **any** apply:

- the destination is **external** or reputation-flagged,
- the content is executed in memory (`IEX`),
- the parent is an Office application or browser,
- it runs on a sensitive host, or the same pattern appears across multiple hosts.

## Containment

1. **Isolate** the host if malicious retrieval/execution is confirmed.
2. **Capture** the full URL and, if retrievable, the downloaded script for analysis.
3. **Block** the domain/IP at the proxy/firewall and add the indicator to detections.
4. **Hunt** for the retrieved payload and the same cradle pattern across the estate.
5. **Reset credentials** for the account if follow-on activity is suspected.
