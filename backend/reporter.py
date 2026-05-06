"""Vulnerability report aggregator and writer.

Collects findings from all investigator swarms and writes structured
JSON and Markdown reports.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def collect_reports(results: dict[str, dict]) -> list[dict]:
    """Extract vulnerability findings from coordinator results.

    Args:
        results: The ``deps.results`` dict from the coordinator —
                 ``{challenge_name: {"flag": <report_json_str>, ...}}``.
    """
    findings: list[dict] = []
    for challenge_name, data in results.items():
        raw = data.get("flag") or data.get("report")
        if not raw:
            continue
        try:
            finding = json.loads(raw) if isinstance(raw, str) else raw
            finding.setdefault("challenge_name", challenge_name)
            findings.append(finding)
        except (json.JSONDecodeError, TypeError):
            # Flag field may be plain text — wrap it
            findings.append(
                {
                    "challenge_name": challenge_name,
                    "raw_output": str(raw)[:2000],
                    "cve_id": "UNKNOWN",
                    "severity": "UNKNOWN",
                }
            )
    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 4))
    return findings


def write_json_report(findings: list[dict], output_path: str) -> None:
    """Write findings to a JSON file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": datetime.now(datetime.UTC).isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("JSON report written: %s", output_path)


def write_markdown_report(findings: list[dict], output_path: str, scan_targets: list[str] | None = None) -> None:
    """Write findings to a Markdown report."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# Vulnerability Analysis Report",
        "",
        f"**Generated**: {now}  ",
        f"**Total findings analyzed**: {len(findings)}",
        "",
    ]

    if scan_targets:
        lines += ["## Scanned Targets", ""]
        for t in scan_targets:
            lines.append(f"- {t}")
        lines.append("")

    if not findings:
        lines += ["## Findings", "", "_No vulnerabilities analyzed._", ""]
    else:
        # Summary table
        critical = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
        high = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
        lines += [
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| CRITICAL | {critical} |",
            f"| HIGH     | {high} |",
            f"| **Total** | **{len(findings)}** |",
            "",
            "## Detailed Findings",
            "",
        ]
        for i, finding in enumerate(findings, 1):
            cve = finding.get("cve_id", "UNKNOWN")
            severity = finding.get("severity", "UNKNOWN")
            pkg = finding.get("pkg_name", "unknown")
            version = finding.get("installed_version", "?")
            fixed = finding.get("fixed_version", "N/A")
            root_cause = finding.get("root_cause", "_Not analyzed_")
            attack = finding.get("attack_scenario", "_Not analyzed_")
            impact = finding.get("impact", "_Not analyzed_")
            remediation = finding.get("remediation", "_Not analyzed_")
            confidence = finding.get("confidence", "unknown")
            poc_feasible = finding.get("poc_feasible", False)
            poc_desc = finding.get("poc_description", None)
            raw_output = finding.get("raw_output", None)

            lines += [
                f"### {i}. {cve} — {pkg} ({severity})",
                "",
                f"**Package**: `{pkg}` version `{version}`  ",
                f"**Fixed in**: `{fixed}`  ",
                f"**Confidence**: {confidence}  ",
                "",
                "#### Root Cause",
                root_cause,
                "",
                "#### Theoretical Attack Scenario",
                attack,
                "",
                "#### Impact",
                impact,
                "",
            ]

            if poc_feasible and poc_desc:
                lines += [
                    "#### Proof of Concept (Local)",
                    poc_desc,
                    "",
                ]

            lines += [
                "#### Remediation",
                remediation,
                "",
                "---",
                "",
            ]

            if raw_output:
                lines += [
                    "#### Raw Output",
                    "```",
                    raw_output[:1000],
                    "```",
                    "",
                    "---",
                    "",
                ]

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    logger.info("Markdown report written: %s", output_path)


def write_reports(
    results: dict[str, dict],
    output_dir: str,
    scan_targets: list[str] | None = None,
) -> tuple[str, str]:
    """Collect findings and write both JSON and Markdown reports.

    Returns:
        Tuple of (json_path, markdown_path).
    """
    findings = collect_reports(results)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = str(out / "vuln_report.json")
    md_path = str(out / "vuln_report.md")

    write_json_report(findings, json_path)
    write_markdown_report(findings, md_path, scan_targets=scan_targets)

    return json_path, md_path
