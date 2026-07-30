#!/usr/bin/env python3
"""Convert the normalized findings model into SARIF 2.1.0.

GitHub code scanning ingests SARIF and renders findings in the Security tab with
severity, location, and remediation context. This lets the automated pentest
pipeline surface results inline on releases instead of only in a markdown report.

Severity mapping (SARIF `level`):  critical/high -> error, medium -> warning,
low/info/unknown -> note. The original severity is preserved in `properties` and
in the rule's `security-severity` (0-10) so GitHub sorts them correctly.
"""
import argparse
import json
from pathlib import Path

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "note",
}
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
    "unknown": "0.0",
}


def build_sarif(doc: dict) -> dict:
    findings = doc.get("findings", [])
    target = doc.get("target", {})

    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("rule_id") or f.get("source") or "finding"
        severity = f.get("severity", "unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace(":", "_").replace("-", "_"),
                "shortDescription": {"text": (f.get("title") or rule_id)[:120]},
                "properties": {
                    "tags": [f.get("source", "scanner"), f.get("category", "")],
                    "security-severity": SECURITY_SEVERITY.get(severity, "0.0"),
                },
            }
        location_uri = f.get("location") or target.get("url") or "urn:target:unknown"
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(severity, "note"),
                "message": {"text": f.get("description") or f.get("title") or rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location_uri},
                        }
                    }
                ],
                "properties": {
                    "severity": severity,
                    "source": f.get("source", ""),
                    "references": f.get("references", []),
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lattix-cicd-pentest",
                        "informationUri": "https://github.com/LATTIX-IO/lattix-cicd-pentest",
                        "version": doc.get("version", "1.0.0"),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": target,
                    "summary": doc.get("summary", {}),
                    "generatedAt": doc.get("generatedAt", ""),
                },
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert normalized findings to SARIF 2.1.0")
    parser.add_argument("findings", help="Path to findings.normalized.json")
    parser.add_argument("--out", default="", help="Output path (defaults to <run_dir>/findings.sarif)")
    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        raise SystemExit(f"findings document not found: {findings_path}")

    doc = json.loads(findings_path.read_text(encoding="utf-8"))
    sarif = build_sarif(doc)

    out_path = Path(args.out) if args.out else (findings_path.parent / "findings.sarif")
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
