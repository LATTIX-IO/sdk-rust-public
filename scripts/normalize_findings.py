#!/usr/bin/env python3
"""Normalize heterogeneous scanner output into one machine-readable findings model.

Reads the raw artifacts produced by run_blackbox_scans (nuclei, OWASP ZAP, nikto,
nmap, whatweb) from a scan run directory and emits a single normalized JSON document
(`findings.normalized.json`) plus a severity summary. This normalized model is the
contract that the severity gate (gate.py) and SARIF exporter (to_sarif.py) build on,
so every downstream consumer sees the same shape regardless of which tool found what.

Black-box only: this script parses scanner artifacts, it never touches the target.
"""
import argparse
import json
import re
from datetime import datetime, UTC
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "reports" / "raw"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
# ZAP riskcode -> normalized severity
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def latest_run_dir() -> Path:
    runs = [p for p in RAW_DIR.glob("*") if p.is_dir()]
    if not runs:
        raise SystemExit("No scan runs found under reports/raw")
    return sorted(runs)[-1]


def read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def norm_severity(value: str) -> str:
    v = (value or "").strip().lower()
    return v if v in SEVERITY_ORDER else "unknown"


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_nuclei(run_dir: Path) -> list[dict]:
    path = run_dir / "nuclei.json"
    text = read_text(path).strip()
    if not text:
        return []
    rows = []
    if text.startswith("["):
        rows = read_json(path, [])
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue

    findings = []
    for i, row in enumerate(rows):
        info = (row or {}).get("info") or {}
        template = row.get("template-id") or row.get("templateID") or f"nuclei-{i}"
        location = row.get("matched-at") or row.get("matched_at") or row.get("host") or ""
        findings.append(
            {
                "id": f"nuclei:{template}:{i}",
                "source": "nuclei",
                "rule_id": str(template),
                "title": info.get("name") or str(template),
                "severity": norm_severity(info.get("severity")),
                "category": ",".join(_as_list(info.get("tags"))) or "template",
                "location": location,
                "description": info.get("description") or "",
                "evidence": row.get("extracted-results") or row.get("matcher-name") or "",
                "references": _as_list(info.get("reference")),
            }
        )
    return findings


def parse_zap(run_dir: Path) -> list[dict]:
    data = read_json(run_dir / "zap.json", {})
    if not isinstance(data, dict):
        return []
    findings = []
    for site in _as_list(data.get("site")):
        site_name = site.get("@name", "") if isinstance(site, dict) else ""
        for j, alert in enumerate(_as_list(site.get("alerts"))):
            instances = _as_list(alert.get("instances"))
            first_uri = ""
            if instances and isinstance(instances[0], dict):
                first_uri = instances[0].get("uri", "")
            findings.append(
                {
                    "id": f"zap:{alert.get('pluginid', j)}:{j}",
                    "source": "zap",
                    "rule_id": str(alert.get("pluginid", "")),
                    "title": alert.get("alert") or alert.get("name") or "ZAP alert",
                    "severity": ZAP_RISK.get(str(alert.get("riskcode", "0")), "info"),
                    "category": "web",
                    "location": first_uri or site_name,
                    "description": re.sub(r"<[^>]+>", "", alert.get("desc", "") or "").strip(),
                    "evidence": (instances[0].get("evidence", "") if instances and isinstance(instances[0], dict) else ""),
                    "references": [r for r in re.sub(r"<[^>]+>", " ", alert.get("reference", "") or "").split() if r.startswith("http")],
                }
            )
    return findings


def parse_nikto(run_dir: Path) -> list[dict]:
    text = read_text(run_dir / "nikto.txt")
    findings = []
    skip_prefixes = ("+ Target", "+ Start Time", "+ End Time", "+ Server:", "+ Scan terminated", "+ 0 host", "+ SSL Info")
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line.startswith("+ ") or line.startswith(skip_prefixes):
            continue
        body = line[2:].strip()
        if not body:
            continue
        findings.append(
            {
                "id": f"nikto:{i}",
                "source": "nikto",
                "rule_id": "nikto-observation",
                "title": body[:120],
                "severity": "info",
                "category": "web-server",
                "location": "",
                "description": body,
                "evidence": "",
                "references": [],
            }
        )
    return findings


def parse_nmap_tls(run_dir: Path) -> list[dict]:
    """Surface missing HTTP security headers and weak-TLS signals as findings.

    Header gaps are flagged 'low' (defense-in-depth); explicit weak-cipher/SSLv*
    markers are flagged 'medium'. Everything here is observed from nmap script output.
    """
    text = read_text(run_dir / "nmap_tls_headers.txt")
    if not text:
        return []
    findings = []
    expected_headers = {
        "strict-transport-security": "Strict-Transport-Security (HSTS) not observed",
        "x-content-type-options": "X-Content-Type-Options (nosniff) not observed",
        "x-frame-options": "X-Frame-Options / frame-ancestors not observed",
        "content-security-policy": "Content-Security-Policy not observed",
    }
    lowered = text.lower()
    # http-security-headers script prints present headers; flag the absent ones.
    if "http-security-headers" in lowered or "syn-ack" in lowered:
        for header, msg in expected_headers.items():
            if header not in lowered:
                findings.append(
                    {
                        "id": f"tls-headers:{header}",
                        "source": "nmap-tls",
                        "rule_id": f"missing-header:{header}",
                        "title": msg,
                        "severity": "low",
                        "category": "transport_tls_headers",
                        "location": "",
                        "description": msg,
                        "evidence": "",
                        "references": [],
                    }
                )
    for marker, title in (
        ("sslv3", "SSLv3 supported (deprecated, insecure)"),
        ("tlsv1.0", "TLS 1.0 supported (deprecated)"),
        ("tlsv1.1", "TLS 1.1 supported (deprecated)"),
        ("rc4", "RC4 cipher offered (weak)"),
        ("export", "EXPORT-grade cipher offered (weak)"),
    ):
        if marker in lowered:
            findings.append(
                {
                    "id": f"tls-weak:{marker}",
                    "source": "nmap-tls",
                    "rule_id": f"weak-tls:{marker}",
                    "title": title,
                    "severity": "medium",
                    "category": "transport_tls_headers",
                    "location": "",
                    "description": title,
                    "evidence": "",
                    "references": [],
                }
            )
    return findings


def parse_open_ports(run_dir: Path) -> list[dict]:
    text = read_text(run_dir / "nmap.txt")
    findings = []
    for i, line in enumerate(text.splitlines()):
        if re.search(r"\bopen\b", line) and "/tcp" in line:
            findings.append(
                {
                    "id": f"nmap-port:{i}",
                    "source": "nmap",
                    "rule_id": "open-port",
                    "title": f"Open port/service: {line.strip()}",
                    "severity": "info",
                    "category": "api_surface",
                    "location": line.strip().split()[0] if line.strip() else "",
                    "description": line.strip(),
                    "evidence": "",
                    "references": [],
                }
            )
    return findings


# --- Extended AppSec / threat-model / red-team parsers --------------------------
# These ingest the output of the run_security_suite.py scanners (config/scanners.json).
# Every parser is defensive: missing/empty/malformed files yield no findings, never
# an exception, so a partial suite run still normalizes cleanly.

def _sarif_severity(result: dict, rules_by_id: dict) -> str:
    """Map a SARIF result to a normalized severity.

    Prefers the rule's numeric security-severity (CVSS-like 0-10); falls back to
    the SARIF result level (error/warning/note).
    """
    rule = rules_by_id.get(result.get("ruleId", ""), {})
    sec = (rule.get("properties") or {}).get("security-severity")
    if sec is not None:
        try:
            score = float(sec)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0.0:
                return "low"
            return "info"
        except (TypeError, ValueError):
            pass
    level = (result.get("level") or "").lower()
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "info")


def parse_sarif_dir(run_dir: Path) -> list[dict]:
    findings: list[dict] = []
    for path in sorted(run_dir.glob("*.sarif")):
        if path.name == "findings.sarif":  # our own export — never re-ingest
            continue
        data = read_json(path, {})
        if not isinstance(data, dict):
            continue
        for run in _as_list(data.get("runs")):
            driver = (((run or {}).get("tool") or {}).get("driver")) or {}
            tool_name = (driver.get("name") or path.stem).lower()
            rules_by_id = {r.get("id"): r for r in _as_list(driver.get("rules")) if isinstance(r, dict)}
            for i, res in enumerate(_as_list(run.get("results"))):
                if not isinstance(res, dict):
                    continue
                loc = ""
                for location in _as_list(res.get("locations")):
                    phys = (location or {}).get("physicalLocation") or {}
                    art = (phys.get("artifactLocation") or {}).get("uri")
                    if art:
                        region = phys.get("region") or {}
                        loc = f"{art}:{region.get('startLine')}" if region.get("startLine") else art
                        break
                msg = (res.get("message") or {}).get("text") or ""
                findings.append(
                    {
                        "id": f"{tool_name}:{res.get('ruleId', i)}:{i}",
                        "source": tool_name,
                        "rule_id": str(res.get("ruleId", tool_name)),
                        "title": (msg.splitlines()[0] if msg else str(res.get("ruleId", tool_name)))[:160],
                        "severity": _sarif_severity(res, rules_by_id),
                        "category": "sast/sca/iac",
                        "location": loc,
                        "description": msg,
                        "evidence": "",
                        "references": [],
                    }
                )
    return findings


def parse_trufflehog(run_dir: Path) -> list[dict]:
    text = read_text(run_dir / "trufflehog.json")
    findings = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        detector = row.get("DetectorName") or row.get("detector_name") or "secret"
        verified = bool(row.get("Verified") or row.get("verified"))
        meta = (row.get("SourceMetadata") or {}).get("Data") or {}
        fs = (meta.get("Filesystem") or {}) if isinstance(meta, dict) else {}
        findings.append(
            {
                "id": f"trufflehog:{detector}:{i}",
                "source": "trufflehog",
                "rule_id": f"secret:{detector}",
                "title": f"{'Verified' if verified else 'Unverified'} secret: {detector}",
                "severity": "high" if verified else "medium",
                "category": "secrets",
                "location": fs.get("file", "") if isinstance(fs, dict) else "",
                "description": f"{detector} credential detected ({'verified live' if verified else 'unverified'}).",
                "evidence": row.get("Redacted", ""),
                "references": [],
            }
        )
    return findings


def _prowler_files(run_dir: Path):
    yield from run_dir.glob("prowler*.json")
    yield from run_dir.glob("*.ocsf.json")


def parse_prowler(run_dir: Path) -> list[dict]:
    findings = []
    seen = set()
    for path in _prowler_files(run_dir):
        if path in seen:
            continue
        seen.add(path)
        data = read_json(path, [])
        rows = data if isinstance(data, list) else _as_list(data.get("findings") if isinstance(data, dict) else None)
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            status = str(row.get("status_code") or row.get("status") or "").upper()
            if status not in ("FAIL", "FAILED", "ALARM"):
                continue
            info = row.get("finding_info") or {}
            resources = _as_list(row.get("resources"))
            res_name = resources[0].get("name", "") if resources and isinstance(resources[0], dict) else ""
            findings.append(
                {
                    "id": f"prowler:{path.stem}:{i}",
                    "source": "prowler",
                    "rule_id": str(info.get("uid") or row.get("check_id") or "prowler-check"),
                    "title": (info.get("title") or row.get("check_title") or "Cloud misconfiguration")[:160],
                    "severity": norm_severity(str(row.get("severity", "medium"))),
                    "category": "cloud_misconfiguration",
                    "location": res_name,
                    "description": info.get("desc") or row.get("status_detail") or "",
                    "evidence": "",
                    "references": [],
                }
            )
    return findings


def parse_kube_bench(run_dir: Path) -> list[dict]:
    data = read_json(run_dir / "kube-bench.json", {})
    if not isinstance(data, dict):
        return []
    findings = []
    for control in _as_list(data.get("Controls")):
        for test in _as_list(control.get("tests")):
            for j, result in enumerate(_as_list(test.get("results"))):
                status = str(result.get("status", "")).upper()
                if status not in ("FAIL", "WARN"):
                    continue
                num = result.get("test_number", j)
                findings.append(
                    {
                        "id": f"kube-bench:{num}:{j}",
                        "source": "kube-bench",
                        "rule_id": f"cis:{num}",
                        "title": (result.get("test_desc") or "CIS k8s benchmark")[:160],
                        "severity": "medium" if status == "FAIL" else "low",
                        "category": "kubernetes_exposure",
                        "location": str(num),
                        "description": result.get("remediation") or result.get("test_desc") or "",
                        "evidence": "",
                        "references": [],
                    }
                )
    return findings


def parse_kube_hunter(run_dir: Path) -> list[dict]:
    data = read_json(run_dir / "kube-hunter.json", {})
    if not isinstance(data, dict):
        return []
    findings = []
    for i, vuln in enumerate(_as_list(data.get("vulnerabilities"))):
        if not isinstance(vuln, dict):
            continue
        findings.append(
            {
                "id": f"kube-hunter:{vuln.get('vid', i)}:{i}",
                "source": "kube-hunter",
                "rule_id": str(vuln.get("vid") or "kube-hunter"),
                "title": (vuln.get("vulnerability") or "Kubernetes exposure")[:160],
                "severity": norm_severity(str(vuln.get("severity", "medium"))),
                "category": "kubernetes_exposure",
                "location": vuln.get("location", ""),
                "description": vuln.get("description", ""),
                "evidence": vuln.get("evidence", ""),
                "references": [vuln["avd_reference"]] if vuln.get("avd_reference") else [],
            }
        )
    return findings


def parse_promptfoo(run_dir: Path) -> list[dict]:
    data = read_json(run_dir / "promptfoo.json", {})
    if not isinstance(data, dict):
        return []
    results = (data.get("results") or {}).get("results")
    if results is None:
        results = data.get("results") if isinstance(data.get("results"), list) else []
    findings = []
    for i, r in enumerate(_as_list(results)):
        if not isinstance(r, dict) or r.get("success", True):
            continue
        meta = ((r.get("testCase") or {}).get("metadata")) or {}
        plugin = meta.get("pluginId") or meta.get("plugin") or "llm-redteam"
        grading = r.get("gradingResult") or {}
        findings.append(
            {
                "id": f"promptfoo:{plugin}:{i}",
                "source": "promptfoo",
                "rule_id": f"llm:{plugin}",
                "title": f"LLM red-team failure: {plugin}"[:160],
                "severity": norm_severity(str(meta.get("severity", "high"))),
                "category": "llm_security",
                "location": "",
                "description": grading.get("reason") or "Model produced an unsafe/exploitable response.",
                "evidence": (str(r.get("response", ""))[:400]),
                "references": [],
            }
        )
    return findings


def parse_garak(run_dir: Path) -> list[dict]:
    # garak writes <prefix>.report.jsonl; pick the first matching report.
    reports = sorted(run_dir.glob("garak*.report.jsonl")) + sorted(run_dir.glob("garak*.jsonl"))
    findings = []
    for path in reports[:1]:
        for i, line in enumerate(read_text(path).splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("entry_type") != "eval":
                continue
            total = row.get("total") or 0
            passed = row.get("passed")
            if passed is None or total == 0 or passed >= total:
                continue
            ratio = (total - passed) / total
            findings.append(
                {
                    "id": f"garak:{row.get('probe', i)}:{i}",
                    "source": "garak",
                    "rule_id": f"llm:{row.get('probe', 'garak')}",
                    "title": f"LLM vulnerability: {row.get('probe', 'garak probe')} ({row.get('detector', '')})"[:160],
                    "severity": "high" if ratio >= 0.5 else "medium",
                    "category": "llm_security",
                    "location": "",
                    "description": f"{total - passed}/{total} attempts hit ({row.get('detector', '')}).",
                    "evidence": "",
                    "references": [],
                }
            )
    return findings


def parse_schemathesis(run_dir: Path) -> list[dict]:
    path = run_dir / "schemathesis.junit.xml"
    if not path.exists():
        return []
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(read_text(path))
    except Exception:
        return []
    findings = []
    for i, case in enumerate(root.iter("testcase")):
        problems = list(case.findall("failure")) + list(case.findall("error"))
        if not problems:
            continue
        name = case.get("name", f"case-{i}")
        msg = problems[0].get("message", "") or (problems[0].text or "")
        findings.append(
            {
                "id": f"schemathesis:{i}",
                "source": "schemathesis",
                "rule_id": "api-contract-violation",
                "title": f"API check failed: {name}"[:160],
                "severity": "medium",
                "category": "api_surface",
                "location": name,
                "description": msg.strip()[:600],
                "evidence": "",
                "references": [],
            }
        )
    return findings


def parse_threagile(run_dir: Path) -> list[dict]:
    data = read_json(run_dir / "risks.json", None)
    if data is None:
        return []
    # Threagile risks.json may be a flat list or a dict keyed by category.
    rows = []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for v in data.values():
            rows.extend(_as_list(v))
    sev_map = {"critical": "critical", "high": "high", "elevated": "high", "medium": "medium", "low": "low"}
    findings = []
    for i, risk in enumerate(rows):
        if not isinstance(risk, dict):
            continue
        sev = sev_map.get(str(risk.get("severity", "")).lower(), "info")
        findings.append(
            {
                "id": f"threagile:{risk.get('synthetic_id', i)}",
                "source": "threagile",
                "rule_id": str(risk.get("category") or "threat"),
                "title": (risk.get("title") or "Modeled threat")[:160],
                "severity": sev,
                "category": "threat_model",
                "location": risk.get("most_relevant_technical_asset") or risk.get("most_relevant_data_asset") or "",
                "description": risk.get("title") or "",
                "evidence": f"likelihood={risk.get('exploitation_likelihood', '')} impact={risk.get('exploitation_impact', '')}",
                "references": [],
            }
        )
    return findings


def parse_extended(run_dir: Path) -> list[dict]:
    findings: list[dict] = []
    findings += parse_sarif_dir(run_dir)
    findings += parse_trufflehog(run_dir)
    findings += parse_prowler(run_dir)
    findings += parse_kube_bench(run_dir)
    findings += parse_kube_hunter(run_dir)
    findings += parse_promptfoo(run_dir)
    findings += parse_garak(run_dir)
    findings += parse_schemathesis(run_dir)
    findings += parse_threagile(run_dir)
    return findings


def summarize(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.get("severity", "unknown")] += 1
    counts["total"] = len(findings)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize scanner output into a unified findings model")
    parser.add_argument("run_dir", nargs="?", default="", help="Scan run directory (defaults to latest under reports/raw)")
    parser.add_argument("--out", default="", help="Output path (defaults to <run_dir>/findings.normalized.json)")
    args = parser.parse_args()

    run_dir = Path(args.run_dir) if args.run_dir else latest_run_dir()
    if not run_dir.exists():
        raise SystemExit(f"Run dir does not exist: {run_dir}")

    meta = read_json(run_dir / "scan_meta.json", {})

    findings: list[dict] = []
    # Black-box DAST scanners
    findings += parse_nuclei(run_dir)
    findings += parse_zap(run_dir)
    findings += parse_nikto(run_dir)
    findings += parse_nmap_tls(run_dir)
    findings += parse_open_ports(run_dir)
    # Extended suite: SAST/SCA/IaC (SARIF), secrets, cloud, k8s, LLM, API, threat-model
    findings += parse_extended(run_dir)

    # Stable ordering: by severity rank, then source, then id.
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.get("severity", "unknown")), f.get("source", ""), f.get("id", "")))

    document = {
        "version": "1.0.0",
        "generatedAt": datetime.now(UTC).isoformat(),
        "run_dir": str(run_dir),
        "target": {
            "url": meta.get("target_url", "unknown"),
            "dns": meta.get("target_dns", "unknown"),
            "profile": meta.get("profile", "unknown"),
        },
        "tools": meta.get("tools", []),
        "summary": summarize(findings),
        "findings": findings,
    }

    out_path = Path(args.out) if args.out else (run_dir / "findings.normalized.json")
    out_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
