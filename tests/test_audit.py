import unittest
from datetime import date

from firewall_auditor.audit import audit
from firewall_auditor.models import Rule


class AuditTests(unittest.TestCase):
    def test_flags_critical_and_expired_rule(self) -> None:
        rule = Rule(1, "open", ("any",), ("any",), ("any",), "allow", True, "", "2025-01-01")
        checks = {finding.check for finding in audit([rule], today=date(2026, 1, 1))}
        self.assertEqual(checks, {"allow-any-any", "expired-rule", "missing-owner"})

    def test_detects_duplicate(self) -> None:
        first = Rule(1, "one", ("a",), ("b",), ("443",), "allow", True, "team", "")
        second = Rule(2, "two", ("a",), ("b",), ("443",), "allow", True, "team", "")
        checks = {finding.check for finding in audit([first, second]) if finding.rule == "two"}
        self.assertIn("duplicate-rule", checks)


if __name__ == "__main__":
    unittest.main()
