"""Trivy vulnerability scanner — async wrapper around the trivy CLI.

Runs `trivy repo --format json --scanners vuln <url>` and parses the output
into structured TrivyFinding objects. Only dependency/OS vulnerability scanning
is enabled (--scanners vuln) to keep token costs low.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Severity order for sorting (highest first)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


@dataclass
class TrivyFinding:
    """A single vulnerability found by Trivy."""

    cve_id: str
    severity: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    title: str
    description: str
    primary_url: str
    target: str  # e.g. "requirements.txt" or "package.json"


@dataclass
class TrivyScanResult:
    """Aggregated result of a Trivy repo scan."""

    target_url: str
    findings: list[TrivyFinding] = field(default_factory=list)
    raw_json: str = ""
    error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    def filter_by_severity(self, min_severity: str = "HIGH") -> list[TrivyFinding]:
        """Return findings at or above the given severity threshold."""
        threshold = SEVERITY_ORDER.get(min_severity.upper(), 1)
        return [f for f in self.findings if SEVERITY_ORDER.get(f.severity, 4) <= threshold]

    def format_summary(self, max_findings: int = 20) -> str:
        """Format a concise summary for the coordinator LLM."""
        top = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 4))[:max_findings]
        lines = [
            f"Trivy scan of: {self.target_url}",
            f"Total findings: {len(self.findings)} "
            f"(CRITICAL: {self.critical_count}, HIGH: {self.high_count})",
            "",
        ]
        for f in top:
            lines.append(
                f"[{f.severity}] {f.cve_id} — {f.pkg_name} {f.installed_version} "
                f"(fix: {f.fixed_version or 'none'}) — {f.title}"
            )
        return "\n".join(lines)


async def trivy_scan(
    target_url: str,
    severity: str = "CRITICAL,HIGH",
    timeout_s: int = 300,
) -> TrivyScanResult:
    """Run `trivy repo` on a URL and return structured results.

    Args:
        target_url: Git repo URL or local path.
        severity: Comma-separated severity filter (e.g. "CRITICAL,HIGH").
        timeout_s: Subprocess timeout in seconds.
    """
    cmd = [
        "trivy", "repo",
        "--format", "json",
        "--scanners", "vuln",
        "--severity", severity,
        "--quiet",
        target_url,
    ]
    logger.info("Running Trivy: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return TrivyScanResult(target_url=target_url, error=f"Trivy timed out after {timeout_s}s")

        raw = stdout.decode("utf-8", errors="replace")
        err_text = stderr.decode("utf-8", errors="replace")

        if proc.returncode not in (0, 1):  # 0 = clean, 1 = non-zero exit-code policy (default: disabled); anything else is an error
            logger.warning("Trivy exit %d: %s", proc.returncode, err_text[:500])
            return TrivyScanResult(
                target_url=target_url,
                raw_json=raw,
                error=f"Trivy exit {proc.returncode}: {err_text[:300]}",
            )

        return _parse_trivy_output(target_url, raw)

    except FileNotFoundError:
        return TrivyScanResult(
            target_url=target_url,
            error="trivy not found — install it or add it to the sandbox image",
        )
    except Exception as e:
        logger.exception("Trivy scan failed: %s", e)
        return TrivyScanResult(target_url=target_url, error=str(e))


def _parse_trivy_output(target_url: str, raw_json: str) -> TrivyScanResult:
    """Parse Trivy JSON output into TrivyFinding objects."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return TrivyScanResult(target_url=target_url, raw_json=raw_json, error=f"JSON parse error: {e}")

    findings: list[TrivyFinding] = []
    for result_block in data.get("Results", []):
        scan_target = result_block.get("Target", "unknown")
        for vuln in result_block.get("Vulnerabilities") or []:
            # Extract primary reference URL
            refs = vuln.get("References") or []
            primary_url = refs[0] if refs else ""
            findings.append(
                TrivyFinding(
                    cve_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    severity=vuln.get("Severity", "UNKNOWN").upper(),
                    pkg_name=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    title=vuln.get("Title", vuln.get("VulnerabilityID", "")),
                    description=(vuln.get("Description") or "")[:500],
                    primary_url=primary_url,
                    target=scan_target,
                )
            )

    # Deduplicate by CVE ID (keep the one with the most info)
    seen: dict[str, TrivyFinding] = {}
    for f in findings:
        if f.cve_id not in seen or len(f.description) > len(seen[f.cve_id].description):
            seen[f.cve_id] = f
    deduped = sorted(seen.values(), key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

    return TrivyScanResult(target_url=target_url, findings=deduped, raw_json=raw_json)
