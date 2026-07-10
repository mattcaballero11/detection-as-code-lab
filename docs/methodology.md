# Methodology

This project treats detections as code: version-controlled, portable, tested, and mapped to a shared threat taxonomy. Sigma is the source of truth; every other artifact derives from it.

## 1. Author in Sigma

Each detection begins as a [Sigma](https://github.com/SigmaHQ/sigma) rule — vendor-neutral YAML that describes the logic once, independent of any SIEM. Every rule follows the standard defined in [`rule-standard.md`](rule-standard.md): a title, stable `id`, description, references, ATT&CK `tags`, `logsource`, detection logic, `condition`, documented false positives, and a severity `level`.

Writing in Sigma first forces the detection intent to be explicit before it gets tangled up in any one platform's query syntax.

## 2. Convert with sigma-cli

The [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) auto-generates platform queries from the Sigma source:

```bash
sigma convert -t kusto  -p microsoft_xdr  <rule.yml>   # Microsoft Sentinel / XDR (KQL)
sigma convert -t splunk -p splunk_windows <rule.yml>   # Splunk (SPL)
```

This step exists to prove **portability** — that one detection can target multiple SIEMs. It also surfaces a practical lesson: a conversion backend needs a **processing pipeline** that matches the target log-source model. Converting to Splunk without a pipeline errors out; the working pipeline here is `splunk_windows` (not `sysmon`, which isn't the installed pipeline name). That's not a rule failure — it's the reality of aligning detection logic to a target schema.

Raw conversion output is saved under `evidence/` as proof of the portability check.

## 3. Hand-review the translations

Auto-conversion proves portability; **hand-review proves engineering judgment.** The refined queries in `translations/kql/` and `translations/spl/` improve on the raw output with:

- deliberate field selection aligned to each platform's data model (see [`field-mapping.md`](field-mapping.md)),
- projected analyst-triage fields (host, user, parent process, command line) so an alert is actionable, not just a boolean,
- realistic data-source assumptions for each SIEM.

> Auto-conversion validates multi-SIEM portability; hand-reviewed KQL and SPL are refined for field mapping, data-source assumptions, and analyst triage needs.

## 4. Validate with synthetic data

Detections are tested **without any real telemetry** using KQL `datatable()` blocks that build fake-but-realistic events inside the query itself. Each test includes at least one **malicious** row (must match) and one **benign** row (must be filtered out), so the test proves the logic *discriminates* rather than merely returning rows.

Tests run in **Azure Log Analytics → Logs**. Because the data is generated in-query, the workspace time range is irrelevant and no connectors, agents, or ingestion are required. Expected result counts per rule are in [`testing-notes.md`](testing-notes.md).

## 5. Map & visualize coverage

Every rule is tagged with its ATT&CK technique, and `navigator/detection_coverage_layer.json` renders those techniques as a coverage layer in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Scores and comments on each technique tie the coloring to specific detections, so the map reflects real coverage rather than decoration.

## 6. Document analyst response

Detection logic is only half the job; an analyst has to act on the alert. `response-playbooks/` captures triage steps, enrichment fields, false-positive guidance, escalation criteria, and containment actions for representative detections — the same thinking that underpins a SOAR runbook.

## Design principles

- **Sigma-first** — one source of truth, many targets.
- **Portability, then judgment** — machine-convert to prove it *can* move; hand-review to make it *good*.
- **Test the discrimination, not just the match** — always include a benign control row.
- **Map everything to ATT&CK** — coverage should be measurable and visual.
- **Lab-safe by construction** — synthetic data only; nothing confidential ever enters the repo.
