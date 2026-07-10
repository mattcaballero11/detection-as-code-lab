# Testing Notes

Recommended evidence levels:

## Level 1: Static validation
- YAML parses successfully.
- `sigma convert` produces KQL/SPL output.
- GitHub Actions validation passes.

## Level 2: Synthetic KQL testing
- Use the `translations/kql_lab_tests/` files.
- Paste one file into Log Analytics, Microsoft Sentinel Logs, or Azure Data Explorer.
- The `datatable()` block creates synthetic events, so no client data is needed.
- Screenshot the returned row as proof that the detection logic works against representative telemetry.

## Level 3: Optional SIEM testing
- Send clean lab Sysmon or Windows Security logs to Splunk/Sentinel.
- Run the SPL or KQL queries against lab-only data.
- Screenshot query hits and field output.

