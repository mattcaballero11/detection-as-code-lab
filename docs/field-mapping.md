# Field Mapping Notes

This project uses Sigma fields as the canonical detection format, then maps selected rules to Microsoft Sentinel-style KQL and Splunk SPL.

| Detection concept | Sigma field | Microsoft XDR / Sentinel-style KQL field | Splunk Sysmon/Security field | Notes |
|---|---|---|---|---|
| Process image | `Image` | `FolderPath` / `FileName` | `Image` | KQL often separates file name and full path. |
| Command line | `CommandLine` | `ProcessCommandLine` | `CommandLine` | Primary process behavior field. |
| Parent process image | `ParentImage` | `InitiatingProcessFileName` / `InitiatingProcessFolderPath` | `ParentImage` | Used for suspicious parent-child relationships. |
| Parent command line | `ParentCommandLine` | `InitiatingProcessCommandLine` | `ParentCommandLine` | Not always present in all telemetry sources. |
| User | `User` | `AccountName` | `User` / `user` | Normalize field casing per platform. |
| Host | `Computer` / `Hostname` | `DeviceName` | `host` / `ComputerName` | Depends on source and collector. |
| Registry key | `TargetObject` | `RegistryKey` | `TargetObject` | Sysmon Event ID 13 maps cleanly here. |
| Registry data | `Details` | `RegistryValueData` | `Details` | Useful for persistence detection. |
| SMB share | `ShareName` | `ShareName` | `ShareName` | Windows Security Event ID 5140. |
| Azure AD user | `UserPrincipalName` | `UserPrincipalName` | `UserPrincipalName` | Cloud identity sign-in logs. |
| Risk events | `RiskEventTypes` | `RiskEventTypes` | `RiskEventTypes` | Entra ID risky sign-in context. |
