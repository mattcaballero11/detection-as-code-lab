# Response Playbook — Suspicious Rundll32 Execution

| | |
| :--- | :--- |
| **Detection** | Suspicious Rundll32 Execution |
| **ATT&CK** | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) — System Binary Proxy Execution: Rundll32 |
| **Tactic** | Defense Evasion |
| **Severity** | Medium–High |

## Detection intent

Flags `rundll32.exe` used to proxy execution of code — a living-off-the-land binary (LOLBin) technique used to bypass application allow-listing. Abuse patterns include loading a DLL from a user-writable path, calling exported functions with suspicious arguments, or `javascript:`/`mshtml` invocations.

## Initial triage

1. **Read the full command line** — which DLL, which exported function, and from what path?
2. **Look for known-abuse patterns** — `javascript:`, `mshtml`, `url.dll,OpenURL`, or a DLL in `Temp`/`AppData`.
3. **Check for abnormal arguments** — rundll32 launched with no/odd arguments, or a raw path, is suspicious.
4. **Identify the parent process** — an Office app or browser parent sharply raises priority.

## Enrichment fields

- The **DLL path and hash/reputation**.
- Parent process (Office/browser = worse).
- `AccountName` / `DeviceName`.
- Any network connections the process initiated.

## False positives

- `rundll32.exe` is used heavily by **legitimate** Windows operations — the technique generates significant benign noise.
- Tune on suspicious **paths and patterns**, not on rundll32 execution itself.

## Escalation criteria

Escalate if **any** apply:

- the DLL loads from a user-writable path,
- `javascript:`/`mshtml` proxy patterns are present,
- the parent is an Office application or browser,
- the process makes an external network callout, or runs on a sensitive host.

## Containment

1. **Isolate** the host if execution is confirmed malicious.
2. **Capture** the DLL and full command line for analysis.
3. **Block and hunt** the DLL hash across the estate.
4. **Investigate the parent** — a malicious macro or document is a common origin.
5. **Reset credentials** if follow-on activity is observed.
