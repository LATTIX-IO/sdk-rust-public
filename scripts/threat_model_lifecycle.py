#!/usr/bin/env python3
"""Create, validate, and update Lattix machine-readable threat models.

The generator is intentionally deterministic and evidence-driven. It creates a
reviewable baseline from repository signals, then incorporates normalized
scanner findings without asking a model to invent architecture or mitigations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "threatmodel" / "lattix-threat-model.schema.json"
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
IGNORED_PARTS = {
    ".git",
    ".idea",
    ".next",
    ".terraform",
    ".venv",
    "dist",
    "node_modules",
    "reports",
    "target",
    "vendor",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def validate_model(model: dict) -> None:
    schema = load_json(SCHEMA_PATH)
    try:
        import jsonschema
    except ImportError:
        required = schema["required"]
        missing = [key for key in required if key not in model]
        if missing:
            raise ValueError(f"threat model is missing required fields: {', '.join(missing)}")
        if model.get("schema_version") != "lattix.threat-model/v1":
            raise ValueError("unsupported threat model schema_version")
        if not isinstance(model.get("threats"), list):
            raise ValueError("threats must be an array")
        for threat in model["threats"]:
            if threat.get("severity") not in SEVERITIES:
                raise ValueError(f"invalid threat severity: {threat.get('severity')}")
        return

    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(model), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:10]
        )
        raise ValueError(f"threat model validation failed: {details}")


def repository_signals(source: Path) -> tuple[list[str], set[str]]:
    relative_files: list[str] = []
    names: set[str] = set()
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        normalized = relative.as_posix().lower()
        relative_files.append(normalized)
        names.add(path.name.lower())
        if len(relative_files) >= 20_000:
            break

    signals = {"source"}
    if "dockerfile" in names or any(name.endswith(".dockerfile") for name in names):
        signals.add("container")
    if any(
        name.endswith((".tf", ".bicep"))
        or "/helm/" in f"/{name}"
        or "/k8s/" in f"/{name}"
        or "/kubernetes/" in f"/{name}"
        for name in relative_files
    ):
        signals.add("deployment")
    if any(
        name.endswith((".proto", ".graphql"))
        or "openapi" in name
        or "swagger" in name
        for name in relative_files
    ):
        signals.add("api")
    if any(
        token in name
        for name in relative_files
        for token in ("auth", "oidc", "oauth", "keycloak", "jwks", "policy")
    ):
        signals.add("identity")
    if any(
        name.endswith((".sql", ".db"))
        or "/migrations/" in f"/{name}"
        or "schema" in name
        for name in relative_files
    ):
        signals.add("data")
    return sorted(signals), names


def baseline_model(source: Path, repository: str, revision: str) -> dict:
    signals, _ = repository_signals(source)
    now = utc_now()
    assets = [
        {
            "id": "source-repository",
            "name": repository,
            "type": "source",
            "description": "Version-controlled application and infrastructure source.",
            "criticality": "high",
        },
        {
            "id": "ci-artifact",
            "name": "CI build artifact",
            "type": "artifact",
            "description": "Artifact produced after required validation and security gates.",
            "criticality": "high",
        },
    ]
    descriptions = {
        "api": ("application-api", "Application API", "api", "Externally or internally callable API surface."),
        "container": ("container-image", "Container image", "container", "Containerized runtime artifact."),
        "deployment": ("deployment-config", "Deployment configuration", "deployment", "Infrastructure and deployment configuration."),
        "identity": ("identity-boundary", "Identity and policy boundary", "identity", "Authentication, authorization, or policy enforcement surface."),
        "data": ("persistent-data", "Persistent data", "data", "Persistent schema or migration-controlled data."),
    }
    for signal in signals:
        if signal not in descriptions:
            continue
        asset_id, name, asset_type, description = descriptions[signal]
        assets.append(
            {
                "id": asset_id,
                "name": name,
                "type": asset_type,
                "description": description,
                "criticality": "critical" if signal in {"identity", "data"} else "high",
            }
        )

    threats = [
        {
            "id": "baseline-supply-chain",
            "title": "Untrusted dependency or build input alters the delivered artifact",
            "category": "software-supply-chain",
            "stride": "supply-chain",
            "severity": "high",
            "status": "modeled",
            "source": "baseline-generator",
            "evidence_refs": [],
        },
        {
            "id": "baseline-secret-disclosure",
            "title": "Credentials or sensitive material are exposed through source or build output",
            "category": "secret-exposure",
            "stride": "information-disclosure",
            "severity": "high",
            "status": "modeled",
            "source": "baseline-generator",
            "evidence_refs": [],
        },
        {
            "id": "baseline-artifact-tampering",
            "title": "An artifact is modified after validation and before publication",
            "category": "artifact-integrity",
            "stride": "tampering",
            "severity": "high",
            "status": "modeled",
            "source": "baseline-generator",
            "evidence_refs": [],
        },
    ]
    if "identity" in signals:
        threats.append(
            {
                "id": "baseline-authz-bypass",
                "title": "A caller bypasses authentication, authorization, or policy enforcement",
                "category": "authorization",
                "stride": "elevation-of-privilege",
                "severity": "critical",
                "status": "modeled",
                "source": "baseline-generator",
                "evidence_refs": [],
            }
        )

    return {
        "schema_version": "lattix.threat-model/v1",
        "metadata": {
            "repository": repository,
            "source_revision": revision,
            "generated": True,
            "generated_at": now,
            "updated_at": now,
        },
        "scope": {
            "description": f"CI security scope for {repository}.",
            "source_root": ".",
            "signals": signals,
        },
        "assets": assets,
        "trust_boundaries": [
            {
                "id": "source-to-ci",
                "name": "Source repository to CI runner",
                "description": "Untrusted change content enters an isolated CI execution environment.",
                "assets": ["source-repository"],
            },
            {
                "id": "ci-to-registry",
                "name": "CI runner to artifact registry",
                "description": "Only validated artifacts may cross into the publication boundary.",
                "assets": ["ci-artifact"],
            },
        ],
        "data_flows": [
            {
                "id": "source-validation",
                "source": "source-repository",
                "destination": "ci-artifact",
                "description": "Tests and security validation transform source into a publishable artifact.",
                "protection": "Required CI checks, isolated runners, least-privilege credentials, and immutable evidence.",
            }
        ],
        "threats": threats,
        "scan_evidence": [],
    }


def prepare(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    if not source.is_dir():
        raise ValueError(f"source directory does not exist: {source}")
    generated = not args.model.is_file()
    if generated:
        model = baseline_model(source, args.repository, args.revision)
    else:
        model = load_json(args.model)
        validate_model(model)
        model["metadata"]["source_revision"] = args.revision
        model["metadata"]["updated_at"] = utc_now()
    validate_model(model)
    write_json(args.output, model)
    print(json.dumps({"model": str(args.output), "generated": generated}))
    return 0


def finding_to_threat(finding: dict) -> dict:
    finding_id = str(finding.get("id") or finding.get("rule_id") or finding.get("title") or "finding")
    category = str(finding.get("category") or "scanner-finding")
    category_lower = category.lower()
    if "secret" in category_lower or "data" in category_lower:
        stride = "information-disclosure"
    elif "auth" in category_lower or "policy" in category_lower:
        stride = "elevation-of-privilege"
    elif "availability" in category_lower or "dos" in category_lower:
        stride = "denial-of-service"
    elif "supply" in category_lower or str(finding.get("source")) in {"grype", "trivy"}:
        stride = "supply-chain"
    else:
        stride = "tampering"
    severity = str(finding.get("severity") or "unknown").lower()
    if severity not in SEVERITIES:
        severity = "unknown"
    return {
        "id": stable_id("observed", finding_id),
        "title": str(finding.get("title") or finding_id)[:240],
        "category": category,
        "stride": stride,
        "severity": severity,
        "status": "observed",
        "source": str(finding.get("source") or "security-suite"),
        "evidence_refs": [finding_id],
    }


def update(args: argparse.Namespace) -> int:
    model = load_json(args.model)
    validate_model(model)
    findings = load_json(args.findings)
    finding_rows = findings.get("findings", [])
    if not isinstance(finding_rows, list):
        raise ValueError("normalized findings document must contain a findings array")

    threats_by_id = {threat["id"]: threat for threat in model["threats"]}
    for finding in finding_rows:
        if not isinstance(finding, dict):
            continue
        threat = finding_to_threat(finding)
        threats_by_id[threat["id"]] = threat
    model["threats"] = sorted(threats_by_id.values(), key=lambda threat: threat["id"])

    run_id = args.run_id or Path(findings.get("run_dir") or args.findings.parent).name
    evidence = {
        "run_id": run_id,
        "generated_at": utc_now(),
        "findings_file": args.findings.name,
        "summary": {
            key: int(value)
            for key, value in (findings.get("summary") or {}).items()
            if isinstance(value, int) and value >= 0
        },
    }
    evidence_by_id = {item["run_id"]: item for item in model["scan_evidence"]}
    evidence_by_id[run_id] = evidence
    model["scan_evidence"] = sorted(evidence_by_id.values(), key=lambda item: item["run_id"])
    model["metadata"]["updated_at"] = utc_now()
    validate_model(model)
    write_json(args.output, model)
    print(str(args.output))
    return 0


def validate(args: argparse.Namespace) -> int:
    validate_model(load_json(args.model))
    print(f"Threat model is valid: {args.model}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare", help="Load or create a baseline threat model")
    prepare_parser.add_argument("--source", type=Path, required=True)
    prepare_parser.add_argument("--model", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--repository", required=True)
    prepare_parser.add_argument("--revision", required=True)
    prepare_parser.set_defaults(handler=prepare)

    update_parser = subparsers.add_parser("update", help="Update a threat model from normalized findings")
    update_parser.add_argument("--model", type=Path, required=True)
    update_parser.add_argument("--findings", type=Path, required=True)
    update_parser.add_argument("--output", type=Path, required=True)
    update_parser.add_argument("--run-id", default="")
    update_parser.set_defaults(handler=update)

    validate_parser = subparsers.add_parser("validate", help="Validate a threat model")
    validate_parser.add_argument("--model", type=Path, required=True)
    validate_parser.set_defaults(handler=validate)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.handler(args)
    except ValueError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
