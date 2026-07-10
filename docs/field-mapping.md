# Field Mapping & Schema Normalization

The same logical field has different names in every SIEM. A detection that works across platforms depends on mapping each concept correctly to each data model — getting this wrong is the most common reason a "translated" rule silently stops matching.

This reference maps the fields used across the detection library.

## Process-creation fields

| Detection concept | Sigma | Microsoft Sentinel (KQL) | Splunk |
| :--- | :--- | :--- | :--- |
| Process image | `Image` | `FileName` / `FolderPath` | `Image` |
| Command line | `CommandLine` | `ProcessCommandLine` | `CommandLine` |
| Parent process | `ParentImage` | `InitiatingProcessFileName` | `ParentImage` |
| User | `User` | `AccountName` | `User` / `user` |
| Host | `Computer` | `DeviceName` | `host` |
| Registry key | `TargetObject` / `RegistryKey` | `RegistryKey` | `TargetObject` |

## Notes on the Microsoft data model

The hand-reviewed KQL targets the **Microsoft Defender / XDR** schema (e.g. `DeviceProcessEvents`), where:

- the acting process is split across `FileName` and `FolderPath` rather than a single `Image` path,
- the initiating (parent) process is prefixed `InitiatingProcess*`,
- identity and device use `AccountName` and `DeviceName`.

When converting with `sigma-cli`, the `microsoft_xdr` pipeline handles most of this automatically; hand-review then confirms the mapping and adds triage fields.

## Why normalization matters

- **Correctness** — an unmapped or mis-mapped field produces a rule that parses cleanly but never fires.
- **Portability** — explicit mappings are what let a single Sigma rule target multiple SIEMs reliably.
- **Onboarding** — when a new log source arrives, a documented mapping table is the difference between a same-day rollout and a week of guesswork.
