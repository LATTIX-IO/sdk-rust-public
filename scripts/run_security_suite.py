#!/usr/bin/env python3
"""Run the extended AppSec / threat-model / red-team suite (config/scanners.json).

Phase-driven orchestrator. Each scanner runs via docker (default) or a local binary,
writes its output into the scan run dir, and is later parsed by normalize_findings.py.
Scanners are SKIPPED (not failed) when their required context, credentials, or binary
are missing — so a partial environment still produces results for the tools it can run.

Phases: shift-left | sbom | cloud | cluster | llm | api | threatmodel | adversary | all

Safety: scanners marked "destructive" (adversary emulation) are off by default and
require PENTEST_ADVERSARY_ACK=I_UNDERSTAND plus an explicit --include of their id.

Examples:
  python scripts/run_security_suite.py --phase shift-left --source .
  python scripts/run_security_suite.py --phase all --dry-run
  python scripts/run_security_suite.py --phase llm --tier 2
"""
import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "reports" / "raw"
REGISTRY = ROOT / "config" / "scanners.json"

ADVERSARY_ACK_VALUE = "I_UNDERSTAND"


def load_registry() -> list[dict]:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return data.get("scanners", [])


def resolve_context(args) -> dict:
    """Resolve substitution + mount context from CLI args and environment."""
    source = args.source or os.getenv("PENTEST_SOURCE_DIR") or str(ROOT)
    target_url = args.target_url or os.getenv("PENTEST_TARGET_URL", "")
    dns = urlparse(target_url).hostname or "" if target_url else ""
    ctx = {
        "out": str(args.run_dir),
        "run_dir": str(args.run_dir),
        "source": str(Path(source).resolve()) if source else "",
        "image": os.getenv("PENTEST_IMAGE", ""),
        "target_url": target_url,
        "target_dns": dns,
        "openapi_url": os.getenv("PENTEST_OPENAPI_URL", ""),
        "k8s_target": os.getenv("PENTEST_K8S_TARGET", "") or dns,
        "kubeconfig": os.getenv("PENTEST_KUBECONFIG", ""),
        "threat_model": os.getenv("PENTEST_THREAT_MODEL", "") or str(ROOT / "threatmodel" / "threagile-model.yaml"),
        "llm_config": os.getenv("PENTEST_LLM_CONFIG", "") or str(ROOT / "config" / "llm-redteam.promptfoo.yaml"),
        "stratus_technique": os.getenv("PENTEST_STRATUS_TECHNIQUE", ""),
        "atomic_technique": os.getenv("PENTEST_ATOMIC_TECHNIQUE", ""),
        "garak_model_type": os.getenv("PENTEST_GARAK_MODEL_TYPE", ""),
        "garak_model_name": os.getenv("PENTEST_GARAK_MODEL_NAME", ""),
    }
    # A 'requires' key referencing a path must also exist on disk to count as present.
    return ctx


def context_present(key: str, ctx: dict) -> bool:
    val = ctx.get(key, "")
    if not val:
        return False
    # File/dir-style context must actually exist.
    if key in ("source", "threat_model", "llm_config", "kubeconfig"):
        return Path(val).exists()
    return True


def select_reason(scanner: dict, args, ctx: dict, dry_run: bool = False) -> str | None:
    """Return a skip reason, or None if the scanner should run."""
    if args.phase != "all" and scanner.get("phase") != args.phase:
        return f"phase != {args.phase}"
    if args.tier and scanner.get("tier") != args.tier:
        return f"tier != {args.tier}"
    if args.include and scanner["id"] not in args.include:
        return "not in --include set"
    if scanner["id"] in (args.exclude or []):
        return "in --exclude set"

    if scanner.get("safety") == "destructive":
        if scanner["id"] not in (args.include or []):
            return "destructive — opt in explicitly with --include"
        if os.getenv("PENTEST_ADVERSARY_ACK") != ADVERSARY_ACK_VALUE:
            return f"destructive — set PENTEST_ADVERSARY_ACK={ADVERSARY_ACK_VALUE}"
    elif not scanner.get("default_enabled", True) and scanner["id"] not in (args.include or []):
        return "disabled by default — opt in with --include"

    for key in scanner.get("requires", []):
        if not context_present(key, ctx):
            return f"missing required context: {key}"
    for env_var in scanner.get("requires_env", []):
        if not os.getenv(env_var):
            return f"missing required env: {env_var}"

    if not dry_run:  # under --dry-run we still surface the intended command
        runner = scanner.get("runner", "docker")
        if runner == "docker" and not shutil.which("docker"):
            return "docker not available"
        if runner == "local":
            cmd = scanner.get("cmd", "")
            if cmd and not shutil.which(cmd):
                return f"local binary not found: {cmd}"
    return None


def build_command(scanner: dict, ctx: dict) -> list[str]:
    runner = scanner.get("runner", "docker")
    sub_args = [a.format(**ctx) if "{" in a else a for a in scanner.get("args", [])]

    if runner == "local":
        return [scanner["cmd"], *sub_args]

    cmd = ["docker", "run", "--rm"]
    if scanner.get("network"):
        cmd += ["--network", scanner["network"]]
    for mount in scanner.get("mounts", []):
        host_val = ctx.get(mount["host"], "")
        if not host_val:
            continue
        spec = f"{Path(host_val).resolve()}:{mount['container']}"
        if mount.get("mode"):
            spec += f":{mount['mode']}"
        cmd += ["-v", spec]
    for env_var in scanner.get("env_passthrough", []):
        if os.getenv(env_var) is not None:
            cmd += ["-e", env_var]
    cmd += [scanner["image"], *sub_args]
    return cmd


def run_scanner(scanner: dict, ctx: dict, dry_run: bool) -> dict:
    command = build_command(scanner, ctx)
    record = {
        "id": scanner["id"],
        "tier": scanner.get("tier"),
        "phase": scanner.get("phase"),
        "format": scanner.get("format"),
        "command": " ".join(command),
        "stdout_to": scanner.get("stdout_to"),
    }
    if dry_run:
        record["status"] = "dry-run"
        return record

    print(f"[suite] running {scanner['id']}")
    try:
        stdout_target = scanner.get("stdout_to")
        if stdout_target:
            out_path = Path(ctx["run_dir"]) / stdout_target
            with open(out_path, "wb") as fh:
                proc = subprocess.run(command, stdout=fh, stderr=subprocess.PIPE)
        else:
            proc = subprocess.run(command, stderr=subprocess.PIPE)
        record["returncode"] = proc.returncode
        ok = proc.returncode == 0 or scanner.get("allow_nonzero_exit", False)
        record["status"] = "ran" if ok else "error"
        if not ok and proc.stderr:
            record["stderr_tail"] = proc.stderr.decode("utf-8", "ignore")[-500:]
    except Exception as exc:  # docker pull failure, image missing, etc.
        record["status"] = "error"
        record["error"] = str(exc)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the extended AppSec / red-team suite")
    parser.add_argument("--phase", default="shift-left",
                        choices=["shift-left", "sbom", "cloud", "cluster", "llm", "api", "threatmodel", "adversary", "all"])
    parser.add_argument("--tier", type=int, default=0, help="Restrict to a tier (1/2/3); 0 = all")
    parser.add_argument("--source", default="", help="Source tree to scan (defaults to PENTEST_SOURCE_DIR or repo root)")
    parser.add_argument("--target-url", default="", help="Target URL (for derived DNS/k8s target)")
    parser.add_argument("--run-dir", default="", help="Output run dir (defaults to a new reports/raw/<ts>)")
    parser.add_argument("--include", nargs="*", default=None, help="Only run these scanner ids (also opts into disabled/destructive ones)")
    parser.add_argument("--exclude", nargs="*", default=None, help="Skip these scanner ids")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without executing")
    parser.add_argument("--fail-on-error", action="store_true", help="Fail when any selected scanner errors")
    parser.add_argument("--require", nargs="*", default=None, help="Fail unless these scanner ids run successfully")
    args = parser.parse_args()

    if not args.run_dir:
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        args.run_dir = RAW_DIR / ts
    args.run_dir = Path(args.run_dir)
    args.run_dir.mkdir(parents=True, exist_ok=True)

    ctx = resolve_context(args)
    scanners = load_registry()

    records = []
    for scanner in scanners:
        reason = select_reason(scanner, args, ctx, dry_run=args.dry_run)
        if reason:
            records.append({"id": scanner["id"], "tier": scanner.get("tier"), "phase": scanner.get("phase"), "status": "skipped", "reason": reason})
            print(f"[suite] skip {scanner['id']}: {reason}")
            continue
        records.append(run_scanner(scanner, ctx, args.dry_run))

    existing_meta = {}
    meta_path = args.run_dir / "suite_meta.json"
    if meta_path.exists():
        try:
            existing_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing_meta = {}
    records_by_id = {
        record["id"]: record
        for record in existing_meta.get("scanners", [])
        if isinstance(record, dict) and record.get("id")
    }
    for record in records:
        prior = records_by_id.get(record["id"])
        phase_filtered = (
            record.get("status") == "skipped"
            and str(record.get("reason", "")).startswith("phase !=")
        )
        if phase_filtered and prior and prior.get("status") in {"ran", "dry-run", "error"}:
            continue
        records_by_id[record["id"]] = record
    completed_phases = list(existing_meta.get("completed_phases", []))
    if args.phase not in completed_phases:
        completed_phases.append(args.phase)

    suite_meta = {
        "generatedAt": datetime.now(UTC).isoformat(),
        "phase": args.phase,
        "completed_phases": completed_phases,
        "tier": args.tier or "all",
        "run_dir": str(args.run_dir),
        "source": ctx["source"],
        "scanners": sorted(records_by_id.values(), key=lambda record: record["id"]),
    }
    meta_path.write_text(json.dumps(suite_meta, indent=2), encoding="utf-8")

    ran = sum(1 for r in records if r["status"] == "ran")
    skipped = sum(1 for r in records if r["status"] == "skipped")
    errored = sum(1 for r in records if r["status"] == "error")
    print(f"[suite] phase={args.phase} ran={ran} skipped={skipped} error={errored} dir={args.run_dir}")
    print(str(args.run_dir))
    required_failures = []
    current_by_id = {record["id"]: record for record in records}
    for scanner_id in args.require or []:
        status = current_by_id.get(scanner_id, {}).get("status", "not-selected")
        if status not in {"ran", "dry-run"}:
            required_failures.append(f"{scanner_id}={status}")
    if required_failures:
        print(f"[suite] required scanners did not complete: {', '.join(required_failures)}")
        return 2
    if args.fail_on_error and errored:
        print("[suite] one or more selected scanners failed")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
