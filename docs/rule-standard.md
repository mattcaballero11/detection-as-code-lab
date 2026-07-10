# Detection Rule Standard

Each detection use case in this repository should include:

1. Sigma source rule under `rules/sigma/`.
2. MITRE ATT&CK tags using `attack.<tactic>` and `attack.<technique_id>` format.
3. Clear detection intent in the `description` field.
4. Relevant telemetry source in `logsource`.
5. False-positive notes.
6. Severity level.
7. KQL translation under `translations/kql/` when applicable.
8. SPL translation under `translations/spl/` when applicable.
9. Optional response playbook under `response-playbooks/`.

Rule status meanings:

- `experimental`: lab-authored rule that needs environment-specific tuning.
- `test`: validated with lab data but not production telemetry.
- `stable`: reviewed and tuned with representative real-world telemetry.

All rules in this portfolio are lab-authored and should be treated as `experimental` unless otherwise stated.
