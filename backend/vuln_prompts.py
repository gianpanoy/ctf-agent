"""Prompts for vulnerability investigation mode.

Provides coordinator and investigator system prompts that replace the CTF-focused
prompts when running in vulnerability scanning mode.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

VULN_COORDINATOR_PROMPT = """\
You are a vulnerability research coordinator managing a team of security investigators.
Your goal is to maximize coverage of reported vulnerabilities by spawning investigators
and guiding their analysis.

Strategy:
- Spawn investigators for all listed vulnerabilities (use spawn_swarm with the exact
  challenge name shown in the vulnerability list)
- Prioritize CRITICAL severity first, then HIGH
- Use read_investigator_trace to monitor progress and provide targeted guidance
- When an investigator is stuck, bump it with specific technical directions

IMPORTANT RULES:
- Investigators perform THEORETICAL analysis only — they do NOT attack live systems
- Their goal is to: (1) understand the vulnerability, (2) describe the theoretical
  attack scenario, (3) identify if a local PoC is feasible in the sandbox, (4) recommend a fix
- Call fetch_challenges first to see all vulnerabilities, then spawn investigators
- Do NOT kill investigators early — let them complete their analysis

You will receive event messages. Respond with tool calls to manage the investigation.
"""


def build_investigator_prompt(
    challenge_dir: str,
    meta_name: str,
    cve_id: str,
    severity: str,
    pkg_name: str,
    installed_version: str,
    fixed_version: str,
    repo_url: str,
    description: str,
    reference_url: str,
) -> str:
    """Build the system prompt for a vulnerability investigator agent."""
    lines: list[str] = [
        "You are a security researcher investigating a vulnerability in open-source software.",
        "Your goal is to analyze this vulnerability thoroughly and produce a structured report.",
        "",
        "## Vulnerability Details",
        f"**CVE ID**          : {cve_id}",
        f"**Severity**        : {severity}",
        f"**Package**         : {pkg_name} @ {installed_version}",
        f"**Fixed version**   : {fixed_version or 'No fix available'}",
        f"**Repository**      : {repo_url}",
        f"**Challenge name**  : {meta_name}",
        "",
        "## Description",
        description or "_No description available._",
        "",
        "## Reference",
        reference_url or "_No reference URL._",
        "",
        "## Your Task",
        "Perform a thorough theoretical security analysis. Work through the following steps:",
        "",
        "1. **Research the CVE** — use `curl` or `bash` to fetch details from:",
        f"   - {reference_url}",
        "   - https://nvd.nist.gov/vuln/detail/" + cve_id,
        "   - https://osv.dev/vulnerability/" + cve_id,
        "",
        "2. **Understand the root cause** — what is the underlying bug?",
        "   (e.g. buffer overflow, SQL injection, deserialization, path traversal, etc.)",
        "",
        "3. **Describe the theoretical attack** — how would an attacker exploit this?",
        "   - What input/conditions are needed?",
        "   - What is the impact? (RCE, data leak, DoS, privilege escalation, etc.)",
        "   - Is authentication required?",
        "",
        "4. **Local PoC (optional)** — if possible in the sandbox environment, write a",
        "   minimal script that demonstrates the vulnerability locally.",
        "   **IMPORTANT**: Do NOT attempt to exploit any live, external, or remote systems.",
        "   Only demonstrate against local/loopback services or test fixtures.",
        "",
        "5. **Remediation** — what is the recommended fix?",
        "   - Upgrade to version: " + (fixed_version or "check vendor advisory"),
        "   - Any additional mitigations or workarounds?",
        "",
        "## Instructions",
        "- Use `bash` to run commands (curl, python3, etc.)",
        "- Clone the repo if needed: `git clone " + repo_url + " /challenge/workspace/repo`",
        "  Then look at the vulnerable package: `find /challenge/workspace/repo -name '*.txt' -o -name '*.json' | head -20`",
        "- Keep your analysis focused — do not spend time on unrelated code",
        "- When your analysis is complete, call: `report_finding '<json>'`",
        "  where <json> is a JSON object with these fields:",
        "  ```json",
        "  {",
        '    "cve_id": "' + cve_id + '",',
        '    "severity": "' + severity + '",',
        '    "pkg_name": "' + pkg_name + '",',
        '    "installed_version": "' + installed_version + '",',
        '    "fixed_version": "' + (fixed_version or "") + '",',
        '    "root_cause": "brief description of the underlying bug",',
        '    "attack_scenario": "how an attacker would exploit this (theoretical)",',
        '    "impact": "what happens if exploited (RCE/leak/DoS/etc.)",',
        '    "poc_feasible": true/false,',
        '    "poc_description": "what the PoC does (or null)",',
        '    "remediation": "how to fix it",',
        '    "confidence": "high/medium/low"',
        "  }",
        "  ```",
        "- Only call report_finding once you have a complete analysis.",
        "- Do NOT attempt to attack or connect to external services.",
    ]

    return "\n".join(lines)


def build_investigator_prompt_from_dir(challenge_dir: str) -> str:
    """Build investigator prompt by reading metadata.yml from a challenge dir."""
    meta_path = Path(challenge_dir) / "metadata.yml"
    if not meta_path.exists():
        return "You are a security researcher. Investigate the vulnerability in /challenge/."

    with open(meta_path) as f:
        data = yaml.safe_load(f) or {}

    # Try to load the finding JSON for richer details
    finding_path = Path(challenge_dir) / "trivy_finding.json"
    finding_data: dict = {}
    if finding_path.exists():
        with open(finding_path) as f:
            finding_data = json.load(f)

    return build_investigator_prompt(
        challenge_dir=challenge_dir,
        meta_name=data.get("name", "Unknown"),
        cve_id=data.get("cve_id", finding_data.get("cve_id", "UNKNOWN")),
        severity=data.get("severity", finding_data.get("severity", "UNKNOWN")),
        pkg_name=data.get("pkg_name", finding_data.get("pkg_name", "")),
        installed_version=data.get("installed_version", finding_data.get("installed_version", "")),
        fixed_version=data.get("fixed_version", finding_data.get("fixed_version", "")),
        repo_url=data.get("repo_url", finding_data.get("repo_url", "")),
        description=data.get("description", ""),
        reference_url=finding_data.get("primary_url", ""),
    )
