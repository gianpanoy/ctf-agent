"""Structured output types for solver agents."""

from pydantic import BaseModel


class FlagFound(BaseModel):
    flag: str
    method: str  # brief description of how


class VulnFound(BaseModel):
    cve_id: str
    severity: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    root_cause: str
    attack_scenario: str
    impact: str
    poc_feasible: bool
    poc_description: str | None
    remediation: str
    confidence: str  # "high" | "medium" | "low"


def vuln_output_json_schema() -> dict:
    """JSON schema for vulnerability investigator structured output."""
    return {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["vuln_found"]},
            "cve_id": {"type": "string"},
            "severity": {"type": "string"},
            "pkg_name": {"type": "string"},
            "installed_version": {"type": "string"},
            "fixed_version": {"type": "string"},
            "root_cause": {"type": "string"},
            "attack_scenario": {"type": "string"},
            "impact": {"type": "string"},
            "poc_feasible": {"type": "boolean"},
            "poc_description": {"type": ["string", "null"]},
            "remediation": {"type": "string"},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        },
        "required": [
            "type", "cve_id", "severity", "pkg_name", "installed_version",
            "fixed_version", "root_cause", "attack_scenario", "impact",
            "poc_feasible", "poc_description", "remediation", "confidence",
        ],
        "additionalProperties": False,
    }


def solver_output_json_schema() -> dict:
    """JSON schema for solver structured output — shared by Claude SDK and Codex.

    Only flag_found is allowed — solvers must keep working until they find a flag.
    No gave_up option forces persistent solving behavior.
    """
    return {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["flag_found"]},
            "flag": {"type": "string"},
            "method": {"type": "string"},
        },
        "required": ["type", "flag", "method"],
        "additionalProperties": False,
    }
