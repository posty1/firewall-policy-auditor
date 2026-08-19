import argparse

from .audit import audit
from .parser import load_rules
from .report import write_reports


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit a firewall policy CSV")
    parser.add_argument("csv", help="Firewall policy CSV")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()
    rules = load_rules(args.csv)
    findings = audit(rules)
    json_path, html_path = write_reports(findings, args.output_dir)
    print(f"Audited {len(rules)} rules; found {len(findings)} issues")
    print(f"JSON: {json_path}\nHTML: {html_path}")


if __name__ == "__main__":
    main()
