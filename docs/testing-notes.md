# Testing Notes

Detections in this repository are validated with **synthetic telemetry** — no real endpoint logs, no client data, no ingestion. Each test builds its own events inside the query using KQL `datatable()`.

## Method

Every test query:

1. Declares a `datatable()` that mimics the relevant table's schema (e.g. `DeviceProcessEvents`).
2. Includes at least one **malicious** row that should match the detection.
3. Includes at least one **benign control** row that should be filtered out.
4. Applies the detection logic and returns only the matching rows.

Because the data is generated in-query, the workspace **time range is irrelevant** and no data sources need to be connected. Tests run in **Azure Log Analytics → Logs → KQL mode**.

A test passes when the malicious row(s) are returned and the benign row(s) are excluded — proving the logic *discriminates*, not merely that it returns something.

## Expected results

| # | Test | Expected rows |
| :-: | :--- | :-: |
| 1 | PowerShell Encoded Command | 1 |
| 2 | PowerShell Download Cradle | 1 |
| 3 | LSASS Memory Dump Attempt | 1 |
| 4 | Registry Run Key Persistence | 1 |
| 5 | Scheduled Task Creation | 1 |
| 6 | Windows Defender Disabled | 2 |
| 7 | Suspicious Rundll32 Execution | 1 |
| 8 | WMI Process Execution | 1 |
| 9 | SMB Admin Share Access | 1 |
| 10 | Azure AD Risky Sign-In | 1 |

> The Windows Defender test intentionally returns **2 rows** because it exercises more than one defense-evasion path (multiple disable methods), each of which should be caught.

## Screenshot index

Validation screenshots are stored in `../screenshots/` using the scheme `05_kql_test_*` through `14_kql_test_*`. Each shows the query, the synthetic data, the detection logic, and the returned result — with the benign control row correctly excluded.

## Splunk validation

For v1, SPL detections are validated via `sigma-cli` conversion and manual review against Windows/Sysmon field mappings (see [`field-mapping.md`](field-mapping.md)). Runtime SPL testing in Splunk Free (local, synthetic event) is planned for a future iteration.
