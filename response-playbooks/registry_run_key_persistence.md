# Response Playbook: Registry Run Key Persistence

## Detection Intent
Identify suspicious modifications to Windows Run and RunOnce registry keys used for persistence.

## ATT&CK Mapping
- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

## Initial Triage
1. Review registry key path, value name, and value data.
2. Identify the initiating process and user.
3. Check whether the binary/script path exists and whether it is signed.
4. Compare with approved startup software and baseline startup entries.

## False Positive Candidates
- Software installers.
- Updaters.
- Messaging or collaboration apps adding startup entries.

## Escalation Criteria
Escalate if the autorun target points to temp/public/user-writable folders, unknown binaries, script interpreters, encoded commands, or recently downloaded files.
