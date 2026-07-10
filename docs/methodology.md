# Methodology

This project follows a detection-as-code workflow:

1. Select a common attacker technique from MITRE ATT&CK.
2. Define the detection intent in plain English.
3. Identify required telemetry.
4. Author a vendor-neutral Sigma rule.
5. Map Sigma fields to target SIEM schema fields.
6. Convert or manually translate the rule to KQL and SPL.
7. Test the rule with synthetic lab events.
8. Document false positives and analyst response steps.
9. Visualize coverage using ATT&CK Navigator.

The purpose is to reproduce detection engineering capability without using client data or proprietary production detections.
