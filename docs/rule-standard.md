# Rule Standard

Every detection in this repository meets a consistent structure and quality bar. Consistency is what makes a detection library maintainable and reviewable — a reader should be able to open any rule and know exactly where to find its logic, its ATT&CK mapping, and its known false positives.

## Required metadata

Each Sigma rule includes:

| Field | Purpose |
| :--- | :--- |
| `title` | Concise, human-readable detection name |
| `id` | Stable UUID so the rule can be referenced across versions |
| `status` | Maturity (e.g. `experimental`, `test`, `stable`) |
| `description` | What the rule detects and why it matters |
| `references` | Source research, ATT&CK page, or vendor docs |
| `author` / `date` / `modified` | Provenance and change history |
| `tags` | MITRE ATT&CK technique(s), e.g. `attack.execution`, `attack.t1059.001` |
| `logsource` | The product/category the rule targets |
| `detection` + `condition` | The matching logic |
| `falsepositives` | Known benign triggers an analyst should expect |
| `level` | Severity (`low` / `medium` / `high` / `critical`) |

## Detection-logic conventions

- Match on **behavior**, not just a single indicator, wherever possible (e.g. an encoded-command *flag pattern* rather than one exact string).
- Keep the `condition` readable; prefer named selection blocks over one dense expression.
- Account for common flag variants (e.g. `-enc`, `-encodedcommand`, `-e`, `/enc`) so trivial evasion doesn't defeat the rule.

## Testing requirement

No rule is considered done until it has a synthetic KQL test in `translations/kql_lab_tests/` that includes **both** a matching (malicious) row and a non-matching (benign control) row, with the expected result count documented in [`testing-notes.md`](testing-notes.md).

## Response requirement

High-value detections carry a matching entry in `response-playbooks/` covering triage, enrichment, false positives, escalation, and containment — so the detection is operationally useful, not just technically correct.
