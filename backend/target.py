"""Target management for vulnerability scanning mode.

Loads scan targets from a YAML file and creates per-finding challenge directories
that are compatible with the existing ChallengeSwarm / ClaudeSolver infrastructure.
"""

from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path

import yaml

from backend.trivy import TrivyFinding, TrivyScanResult


@dataclass
class TargetMeta:
    """A repository or path to scan for vulnerabilities."""

    name: str
    url: str
    description: str = ""
    scan_focus: str = ""  # optional subdirectory to focus on (e.g. "src/")


def load_targets(targets_file: str) -> list[TargetMeta]:
    """Load scan targets from a YAML file.

    Expected format::

        targets:
          - name: my-project
            url: https://github.com/org/repo
            description: "Web API service"
          - name: another-project
            url: /local/path/to/repo
    """
    path = Path(targets_file)
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {targets_file}")
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    raw = data.get("targets", data) if isinstance(data, dict) else data
    if isinstance(raw, list):
        items = raw
    else:
        raise ValueError(f"Expected a list of targets in {targets_file}")
    return [
        TargetMeta(
            name=item.get("name", item.get("url", "unknown")),
            url=item["url"],
            description=item.get("description", ""),
            scan_focus=item.get("scan_focus", ""),
        )
        for item in items
    ]


def _safe_dir_name(text: str) -> str:
    """Convert arbitrary text to a safe directory name."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)[:60].strip("_")


def create_vuln_challenge_dirs(
    scan_result: TrivyScanResult,
    target: TargetMeta,
    output_root: str,
    max_findings: int = 5,
    min_severity: str = "HIGH",
) -> dict[str, str]:
    """Create one challenge directory per top vulnerability finding.

    Returns a mapping of ``{challenge_name: challenge_dir_path}``.
    Each directory contains a ``metadata.yml`` compatible with ChallengeMeta.
    """
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)

    top_findings = scan_result.filter_by_severity(min_severity)[:max_findings]
    challenge_dirs: dict[str, str] = {}

    for finding in top_findings:
        challenge_name = f"{_safe_dir_name(target.name)}__{_safe_dir_name(finding.cve_id)}"
        ch_dir = root / challenge_name
        ch_dir.mkdir(parents=True, exist_ok=True)

        metadata = _build_metadata(finding, target, scan_result.target_url)
        with open(ch_dir / "metadata.yml", "w") as f:
            yaml.dump(metadata, f, default_flow_style=False, allow_unicode=True)

        # Also write the raw finding JSON for deep analysis
        with open(ch_dir / "trivy_finding.json", "w") as f:
            json.dump(
                {
                    "cve_id": finding.cve_id,
                    "severity": finding.severity,
                    "pkg_name": finding.pkg_name,
                    "installed_version": finding.installed_version,
                    "fixed_version": finding.fixed_version,
                    "title": finding.title,
                    "description": finding.description,
                    "primary_url": finding.primary_url,
                    "target_file": finding.target,
                    "repo_url": scan_result.target_url,
                },
                f,
                indent=2,
            )

        challenge_dirs[challenge_name] = str(ch_dir)

    return challenge_dirs


def _build_metadata(
    finding: TrivyFinding,
    target: TargetMeta,
    repo_url: str,
) -> dict:
    """Build a metadata.yml dict compatible with ChallengeMeta."""
    description = textwrap.dedent(f"""
        **CVE**: {finding.cve_id}
        **Severity**: {finding.severity}
        **Package**: {finding.pkg_name} @ {finding.installed_version}
        **Fixed in**: {finding.fixed_version or "no fix available"}
        **Affected file**: {finding.target}
        **Repository**: {repo_url}

        **Title**: {finding.title}

        **Description**:
        {finding.description or "No description available."}

        **Reference**: {finding.primary_url}
    """).strip()

    return {
        "name": f"{finding.cve_id} in {finding.pkg_name} ({target.name})",
        "category": "vulnerability",
        "value": _severity_to_points(finding.severity),
        "description": description,
        "tags": [finding.severity.lower(), "vuln", finding.pkg_name],
        "connection_info": "",
        "hints": [],
        "solves": 0,
        # Extra fields for vuln mode (ignored by ChallengeMeta but readable directly)
        "cve_id": finding.cve_id,
        "severity": finding.severity,
        "pkg_name": finding.pkg_name,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "repo_url": repo_url,
    }


def _severity_to_points(severity: str) -> int:
    return {"CRITICAL": 500, "HIGH": 300, "MEDIUM": 100, "LOW": 50}.get(severity.upper(), 0)
