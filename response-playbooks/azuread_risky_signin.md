# Response Playbook — Azure AD Risky Sign-In / Unlikely Travel

| | |
| :--- | :--- |
| **Detection** | Azure AD Risky Sign-In / Unlikely Travel |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts |
| **Tactic** | Initial Access / Defense Evasion / Persistence |
| **Severity** | High |

## Detection intent

Flags a sign-in that Entra ID (Azure AD) marks risky, or "impossible travel" — two sign-ins from geographically distant locations within a time window too short to travel between them. This is a strong indicator of credential compromise and valid-account abuse in cloud identity.

## Initial triage

1. **Compare the two sign-ins** — locations, IPs, and the time delta between them.
2. **Check MFA** — was multi-factor satisfied, or was this a password-only sign-in?
3. **New device/browser?** — an unfamiliar device raises the risk.
4. **Was it successful or blocked**, and is there **subsequent activity** (new inbox rules, OAuth app consent, mass download, privileged action)?

## Enrichment fields

- **IP reputation** of both sign-ins — VPN, Tor, or hosting-provider ranges?
- The user's **normal locations and devices**.
- Correlate with mailbox activity, OAuth grants, and data-access logs.
- Full Entra ID sign-in log detail for the session.

## False positives

- VPNs, corporate proxies, and legitimate travel routinely trigger impossible-travel alerts.
- Roaming users and cloud-service IPs.
- Tune out sanctioned VPN egress ranges and known corporate IPs.

## Escalation criteria

Escalate if **any** apply:

- a **successful** sign-in from an anomalous location **without MFA**,
- followed by **inbox-rule creation, OAuth consent, mass download, or a privileged action**,
- MFA was disabled or re-registered on the account,
- the account is privileged (admin roles).

## Containment

1. **Revoke sessions** and require re-authentication for the account.
2. **Reset the password** and **re-register MFA**.
3. **Review and revoke** any suspicious inbox rules or OAuth application grants.
4. **Check for data exfiltration** (downloads, forwarding rules, sharing changes).
5. **Investigate the source** — how the credentials were phished or leaked — and notify the user.
