# Detection-as-Code Lab: Sigma to KQL and SPL

## Overview

This repository is a lab-built detection engineering portfolio project. It demonstrates how vendor-neutral Sigma detections can be authored, mapped to MITRE ATT&CK, translated into Microsoft Sentinel-style KQL and Splunk SPL, documented as a reusable detection use-case library, and visualized through ATT&CK Navigator.

No client data, proprietary detections, or production telemetry are included.

## Objectives

- Build a reusable detection use-case library.
- Author Sigma rules mapped to MITRE ATT&CK.
- Translate selected rules into KQL and SPL.
- Document field normalization decisions across SIEM schemas.
- Create ATT&CK Navigator coverage visualization.
- Add response playbooks for analyst triage.

## Detection Coverage

| # | Detection Rule | ATT&CK | Tactic | Sigma | KQL | SPL | Status |
|---|---|---|---|---|---|---|---|
| 1 | Suspicious PowerShell Encoded Command | T1059.001 | Execution | ✅ | ✅ | ✅ | Experimental |
| 2 | Suspicious PowerShell Download Cradle | T1059.001, T1105 | Execution / C2 | ✅ | ✅ | ✅ | Experimental |
| 3 | LSASS Memory Dump Attempt | T1003.001 | Credential Access | ✅ | ✅ | ✅ | Experimental |
| 4 | Registry Run Key Persistence | T1547.001 | Persistence | ✅ | ✅ | ✅ | Experimental |
| 5 | Suspicious Scheduled Task Creation | T1053.005 | Persistence / Execution | ✅ | ✅ | ✅ | Experimental |
| 6 | Windows Defender Disabled via Command Line | T1562.001 | Defense Evasion | ✅ | ✅ | ✅ | Experimental |
| 7 | Suspicious Rundll32 Execution | T1218.011 | Defense Evasion | ✅ | ✅ | ✅ | Experimental |
| 8 | WMI Process Execution via WMIC | T1047 | Execution | ✅ | ✅ | ✅ | Experimental |
| 9 | SMB Admin Share Access | T1021.002 | Lateral Movement | ✅ | ✅ | ✅ | Experimental |
| 10 | Azure AD Risky Sign-In Due to Unlikely Travel | T1078 | Initial Access | ✅ | ✅ | ✅ | Experimental |

## Repository Structure

```text
rules/sigma/             Vendor-neutral Sigma rules
translations/kql/        Human-reviewed KQL translations
translations/spl/        Human-reviewed SPL translations
translations/kql_lab_tests/ Synthetic KQL datatable tests for screenshots
navigator/               ATT&CK Navigator layer JSON
docs/                    Methodology, rule standard, and field mapping notes
response-playbooks/      Analyst triage and response notes
scripts/                 Helper scripts
screenshots/             Portfolio screenshots
```

## Methodology

1. Select a common attacker technique from MITRE ATT&CK.
2. Define detection intent and required telemetry.
3. Author the Sigma rule.
4. Map Sigma fields to Sentinel/KQL and Splunk/SPL fields.
5. Convert or manually translate the rule.
6. Test with synthetic lab events.
7. Document false positives and response steps.
8. Visualize ATT&CK coverage.

## How to Validate Locally

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

# Confirm Sigma tooling is installed
sigma --version
sigma plugin list -t backend

# Convert rules to Splunk or Kusto/KQL-style output
sigma convert -t splunk rules/sigma/windows/process_creation/proc_powershell_encoded_command.yml
sigma convert -t kusto rules/sigma/windows/process_creation/proc_powershell_encoded_command.yml

# List ATT&CK coverage from local rules
python scripts/generate_navigator_layer.py
```

## Screenshot Evidence Checklist

- `01_repo_structure.png` — VS Code or terminal tree view.
- `02_sigma_rule_example.png` — one Sigma rule open in VS Code.
- `03_sigma_conversion.png` — terminal output from `sigma convert`.
- `04_kql_test_hit.png` — KQL lab test returning one synthetic event.
- `05_spl_translation.png` — SPL translation open in VS Code or Splunk.
- `06_attack_navigator_coverage.png` — imported ATT&CK Navigator layer.
- `07_github_actions_pass.png` — GitHub Actions validation passing.

## Disclaimer

This project is for portfolio and educational purposes. The detections are lab-authored, mapped to public ATT&CK techniques, and designed for controlled testing. They require environment-specific tuning before production use.
