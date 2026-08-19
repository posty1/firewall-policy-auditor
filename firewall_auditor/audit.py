from datetime import date

from .models import Finding, Rule


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _covers(broader: tuple[str, ...], narrower: tuple[str, ...]) -> bool:
    return "any" in broader or set(narrower).issubset(broader)


def audit(rules: list[Rule], today: date | None = None) -> list[Finding]:
    today = today or date.today()
    findings: list[Finding] = []
    fingerprints: dict[tuple[object, ...], str] = {}

    for index, rule in enumerate(rules):
        if not rule.enabled:
            findings.append(Finding(rule.name, "low", "disabled-rule", "Rule is disabled and may be removable."))
        if not rule.owner:
            findings.append(Finding(rule.name, "medium", "missing-owner", "Rule has no accountable owner."))
        if rule.expires:
            try:
                if date.fromisoformat(rule.expires) < today:
                    findings.append(Finding(rule.name, "high", "expired-rule", f"Rule expired on {rule.expires}."))
            except ValueError:
                findings.append(Finding(rule.name, "medium", "invalid-expiry", "Expiry is not ISO YYYY-MM-DD."))

        if rule.enabled and rule.action == "allow":
            dimensions = sum("any" in value for value in (rule.source, rule.destination, rule.service))
            if dimensions == 3:
                findings.append(Finding(rule.name, "critical", "allow-any-any", "Allows any source, destination, and service."))
            elif dimensions >= 1:
                findings.append(Finding(rule.name, "high", "broad-allow", "Allow rule contains one or more 'any' fields."))

        fingerprint = (rule.source, rule.destination, rule.service, rule.action, rule.enabled)
        if fingerprint in fingerprints:
            findings.append(Finding(rule.name, "medium", "duplicate-rule", f"Duplicates '{fingerprints[fingerprint]}'."))
        else:
            fingerprints[fingerprint] = rule.name

        for earlier in rules[:index]:
            if (
                earlier.enabled
                and rule.enabled
                and earlier.action == rule.action
                and _covers(earlier.source, rule.source)
                and _covers(earlier.destination, rule.destination)
                and _covers(earlier.service, rule.service)
            ):
                findings.append(Finding(rule.name, "medium", "shadowed-rule", f"Covered by earlier rule '{earlier.name}'."))
                break

    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.rule, item.check))
