# Firewall Policy Auditor

A Python CLI that audits exported firewall rules for common security and hygiene problems: overly permissive access, expired rules, disabled rules, missing ownership, duplicate rules, and shadowed rules.

## Why it exists

Firewall reviews are often spreadsheet-heavy and inconsistent. This tool converts a CSV policy export into repeatable findings and produces both machine-readable JSON and an analyst-friendly HTML report.

## Quick start

```bash
python -m firewall_auditor.cli examples/firewall_rules.csv --output-dir reports
```

No third-party runtime packages are required. Python 3.10+ is recommended.

## Expected CSV columns

`name,source,destination,service,action,enabled,owner,expires`

Multiple values can be separated with semicolons. Networks may be CIDR blocks, IP addresses, named objects, or `any`.

## Checks

- Critical inbound or outbound `any`/`any` allow rules
- Broad sources, destinations, or services
- Expired and disabled rules
- Missing rule owners
- Exact duplicates
- Rules shadowed by an earlier broader rule with the same action

## Test

```bash
python -m unittest discover -s tests -v
```

## Safety

This project is read-only: it never connects to or changes a firewall. Sample data is synthetic.

## Potential integrations

The normalized JSON output can feed Jira, ServiceNow, a SIEM, or a remediation dashboard. Vendor API adapters for Palo Alto Networks, Zscaler, and Cisco could be added without changing the audit engine.

## License

MIT
