#!/usr/bin/env python3
"""Severity gate for CI/CD.

Reads a normalized findings document (from normalize_findings.py) and fails the
build (exit code 2) when observed severity counts exceed the configured thresholds.
Thresholds come from config/gate.json (per profile), and can be overridden per-run
via --max-<sev> flags or PENTEST_GATE_MAX_<SEV> environment variables.

A threshold of -1 means "unlimited" (that severity can never fail the gate).

Exit codes:
  0  gate passed
  2  gate failed (a severity exceeded its threshold)
  3  usage / input error
"""
import argparse
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE_CONFIG = ROOT / "config" / "gate.json"
GATED_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def load_thresholds(profile: str) -> dict:
    defaults = {"max_critical": 0, "max_high": 0, "max_medium": -1, "max_low": -1, "max_info": -1}
    if GATE_CONFIG.exists():
        try:
            cfg = json.loads(GATE_CONFIG.read_text(encoding="utf-8"))
            profile_cfg = (cfg.get("profiles") or {}).get(profile)
            if isinstance(profile_cfg, dict):
                defaults.update({k: v for k, v in profile_cfg.items() if k.startswith("max_")})
        except Exception:
            pass
    return defaults


def apply_overrides(thresholds: dict, args) -> dict:
    for sev in GATED_SEVERITIES:
        key = f"max_{sev}"
        cli_val = getattr(args, key, None)
        if cli_val is not None:
            thresholds[key] = cli_val
            continue
        env_val = os.getenv(f"PENTEST_GATE_MAX_{sev.upper()}")
        if env_val is not None and env_val.strip() != "":
            try:
                thresholds[key] = int(env_val)
            except ValueError:
                pass
    return thresholds


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail CI when findings exceed severity thresholds")
    parser.add_argument("findings", help="Path to findings.normalized.json")
    parser.add_argument("--profile", default=os.getenv("PENTEST_PROFILE", "local"))
    for sev in GATED_SEVERITIES:
        parser.add_argument(f"--max-{sev}", type=int, default=None, dest=f"max_{sev}")
    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"[gate] findings document not found: {findings_path}")
        return 3

    try:
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[gate] could not parse findings document: {exc}")
        return 3

    summary = doc.get("summary", {})
    thresholds = apply_overrides(load_thresholds(args.profile), args)

    print(f"[gate] profile={args.profile} target={doc.get('target', {}).get('url', 'unknown')}")
    print(f"[gate] observed: " + ", ".join(f"{s}={summary.get(s, 0)}" for s in GATED_SEVERITIES))

    breaches = []
    for sev in GATED_SEVERITIES:
        limit = thresholds.get(f"max_{sev}", -1)
        observed = int(summary.get(sev, 0))
        if limit is not None and limit >= 0 and observed > limit:
            breaches.append(f"{sev}: {observed} > allowed {limit}")

    if breaches:
        print("[gate] FAILED - severity thresholds exceeded:")
        for b in breaches:
            print(f"  - {b}")
        return 2

    print("[gate] PASSED - all severities within configured thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
