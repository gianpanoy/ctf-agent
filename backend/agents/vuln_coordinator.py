"""Vulnerability research coordinator.

A simplified coordinator that:
1. Accepts pre-loaded vulnerability challenge directories (generated from Trivy)
2. Uses a stub target client instead of a live CTFd server
3. Runs a lightweight event loop (no poller) that spawns investigator swarms
4. Passes Trivy scan summaries to the coordinator LLM as initial context
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    create_sdk_mcp_server,
    tool,
)

from backend.agents.coordinator_core import (
    do_bump_agent,
    do_check_swarm_status,
    do_kill_swarm,
    do_read_solver_trace,
    do_spawn_swarm,
)
from backend.config import Settings
from backend.cost_tracker import CostTracker
from backend.deps import CoordinatorDeps
from backend.prompts import ChallengeMeta
from backend.vuln_prompts import VULN_COORDINATOR_PROMPT

logger = logging.getLogger(__name__)


class VulnTargetClient:
    """Stub client that satisfies the CTFdClient interface for vulnerability mode.

    Returns pre-loaded vulnerability findings instead of polling a CTFd server.
    No network calls are made.
    """

    def __init__(self, challenge_metas: dict[str, ChallengeMeta]) -> None:
        self._metas = challenge_metas
        self._investigated: set[str] = set()

    async def fetch_all_challenges(self) -> list[dict]:
        return [
            {
                "name": meta.name,
                "category": meta.category,
                "value": meta.value,
                "solves": meta.solves,
                "description": meta.description[:200],
            }
            for meta in self._metas.values()
        ]

    async def fetch_challenge_stubs(self) -> list[dict]:
        return await self.fetch_all_challenges()

    async def fetch_solved_names(self) -> set[str]:
        return set(self._investigated)

    async def submit_flag(self, challenge_name: str, flag: str) -> Any:
        """Mark a finding as investigated and store the report."""
        self._investigated.add(challenge_name)
        return _SubmitResult(status="correct", display="Investigation report accepted.")

    async def pull_challenge(self, ch_data: dict, output_dir: str) -> str:
        raise RuntimeError(
            "VulnTargetClient: pull_challenge called but all challenge dirs are pre-loaded. "
            "Use 'create_vuln_challenge_dirs' before starting the coordinator."
        )

    async def close(self) -> None:
        pass


class _SubmitResult:
    def __init__(self, status: str, display: str) -> None:
        self.status = status
        self.display = display


def _build_vuln_coordinator_mcp(deps: CoordinatorDeps):
    """Build the MCP tool server for the vulnerability coordinator."""

    def _text(s: str) -> dict:
        return {"content": [{"type": "text", "text": s}]}

    @tool("list_vulnerabilities", "List all vulnerability findings with severity, package, and status.", {})
    async def list_vulnerabilities(args: dict) -> dict:
        investigated = await deps.ctfd.fetch_solved_names()
        metas = list(deps.challenge_metas.values())
        result = [
            {
                "name": m.name,
                "severity": next(
                    (t for t in m.tags if t.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW")), "UNKNOWN"
                ).upper(),
                "tags": m.tags,
                "points": m.value,
                "status": "investigated" if m.name in investigated else "pending",
            }
            for m in metas
        ]
        return _text(json.dumps(result, indent=2))

    @tool("get_investigation_status", "Check which vulnerabilities are investigated and which are active.", {})
    async def get_investigation_status(args: dict) -> dict:
        investigated = await deps.ctfd.fetch_solved_names()
        swarm_status = {name: swarm.get_status() for name, swarm in deps.swarms.items()}
        return _text(json.dumps({"investigated": sorted(investigated), "active_swarms": swarm_status}, indent=2))

    @tool("spawn_investigator", "Launch investigator agents on a vulnerability.", {"challenge_name": str})
    async def spawn_investigator(args: dict) -> dict:
        return _text(await do_spawn_swarm(deps, args["challenge_name"]))

    @tool("check_investigator_status", "Get per-agent progress for an active investigation.", {"challenge_name": str})
    async def check_investigator_status(args: dict) -> dict:
        return _text(await do_check_swarm_status(deps, args["challenge_name"]))

    @tool("read_investigator_trace", "Read recent trace events from an investigator agent.", {"challenge_name": str, "model_spec": str, "last_n": int})
    async def read_investigator_trace(args: dict) -> dict:
        return _text(await do_read_solver_trace(deps, args["challenge_name"], args["model_spec"], args.get("last_n", 20)))

    @tool("bump_investigator", "Send targeted guidance to a stuck investigator.", {"challenge_name": str, "model_spec": str, "insights": str})
    async def bump_investigator(args: dict) -> dict:
        return _text(await do_bump_agent(deps, args["challenge_name"], args["model_spec"], args["insights"]))

    @tool("kill_investigator", "Cancel the investigator swarm for a vulnerability.", {"challenge_name": str})
    async def kill_investigator(args: dict) -> dict:
        return _text(await do_kill_swarm(deps, args["challenge_name"]))

    return create_sdk_mcp_server(
        name="vuln_coordinator",
        version="1.0.0",
        tools=[
            list_vulnerabilities, get_investigation_status, spawn_investigator,
            check_investigator_status, read_investigator_trace, bump_investigator,
            kill_investigator,
        ],
    )


async def run_vuln_event_loop(
    deps: CoordinatorDeps,
    turn_fn,
    trivy_summary: str,
    status_interval: int = 60,
) -> dict[str, Any]:
    """Simplified event loop for vulnerability mode — no CTFd poller.

    Auto-spawns investigator swarms for all pre-loaded vulnerability challenge dirs,
    then waits for completion while sending periodic status updates to the coordinator.
    """
    total = len(deps.challenge_metas)
    initial_msg = (
        f"Vulnerability scan complete. {total} findings ready for investigation.\n\n"
        f"{trivy_summary}\n\n"
        "Please call list_vulnerabilities to see all findings, then spawn investigators "
        "for each one using their exact name."
    )

    logger.info(
        "Vuln coordinator starting: %d findings, %d models",
        total,
        len(deps.model_specs),
    )

    try:
        # Initial coordinator turn — gives it the full Trivy context
        await turn_fn(initial_msg)

        # Auto-spawn any remaining uninvestigated findings
        await _auto_spawn_all(deps)

        last_status = asyncio.get_event_loop().time()

        while True:
            # All swarms done?
            active = {n: t for n, t in deps.swarm_tasks.items() if not t.done()}
            if not active and deps.swarms:
                break

            await asyncio.sleep(5)

            parts: list[str] = []

            # Detect finished swarms
            for name, task in list(deps.swarm_tasks.items()):
                if task.done():
                    parts.append(f"INVESTIGATOR FINISHED: '{name}' completed. Check if further analysis needed.")
                    deps.swarm_tasks.pop(name, None)

            # Drain coordinator inbox
            while True:
                try:
                    solver_msg = deps.coordinator_inbox.get_nowait()
                    parts.append(f"INVESTIGATOR MESSAGE: {solver_msg}")
                except asyncio.QueueEmpty:
                    break

            # Periodic status
            now = asyncio.get_event_loop().time()
            if now - last_status >= status_interval:
                last_status = now
                remaining = sum(1 for t in deps.swarm_tasks.values() if not t.done())
                investigated = len(deps.results)
                cost = deps.cost_tracker.total_cost_usd
                status_line = (
                    f"STATUS: {investigated}/{total} investigated, "
                    f"{remaining} active investigators. Cost: ${cost:.2f}"
                )
                if active or parts:
                    parts.append(status_line)
                else:
                    logger.info(status_line)

            if parts:
                msg = "\n\n".join(parts)
                logger.info("Event -> coordinator: %s", msg[:200])
                await turn_fn(msg)

    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Vuln coordinator shutting down...")
    except Exception as e:
        logger.error("Vuln coordinator fatal: %s", e, exc_info=True)
    finally:
        for swarm in deps.swarms.values():
            swarm.kill()
        for task in deps.swarm_tasks.values():
            task.cancel()
        if deps.swarm_tasks:
            await asyncio.gather(*deps.swarm_tasks.values(), return_exceptions=True)
        deps.cost_tracker.log_summary()
        try:
            await deps.ctfd.close()
        except Exception:
            pass

    return {
        "results": deps.results,
        "total_cost_usd": deps.cost_tracker.total_cost_usd,
        "total_tokens": deps.cost_tracker.total_tokens,
    }


async def _auto_spawn_all(deps: CoordinatorDeps) -> None:
    """Spawn investigator swarms for all pre-loaded challenge dirs."""
    for name in list(deps.challenge_dirs):
        if name not in deps.swarms:
            try:
                result = await do_spawn_swarm(deps, name)
                logger.info("Auto-spawned investigator for '%s': %s", name, result[:80])
            except Exception as e:
                logger.warning("Auto-spawn failed for '%s': %s", name, e)


async def run_vuln_coordinator(
    settings: Settings,
    challenge_dirs: dict[str, str],
    challenge_metas: dict[str, ChallengeMeta],
    trivy_summary: str,
    model_specs: list[str],
    coordinator_model: str = "claude-opus-4-6",
    report_output_dir: str = "vuln-reports",
) -> dict[str, Any]:
    """Run the vulnerability research coordinator end-to-end.

    Args:
        settings: Application settings.
        challenge_dirs: Pre-created vuln challenge dirs keyed by challenge name.
        challenge_metas: Loaded ChallengeMeta objects keyed by challenge name.
        trivy_summary: Pre-formatted Trivy scan summary for the coordinator prompt.
        model_specs: Investigator model specs.
        coordinator_model: Claude model ID for the coordinator.
        report_output_dir: Directory to write the final reports.
    """
    stub_ctfd = VulnTargetClient(challenge_metas)
    cost_tracker = CostTracker()

    deps = CoordinatorDeps(
        ctfd=stub_ctfd,  # type: ignore[arg-type]
        cost_tracker=cost_tracker,
        settings=settings,
        model_specs=model_specs,
        challenges_root=report_output_dir,
        no_submit=False,
        max_concurrent_challenges=len(challenge_dirs),
        challenge_dirs=challenge_dirs,
        challenge_metas=challenge_metas,
    )

    # Wire up investigator prompt injection via a custom swarm factory override
    _patch_swarm_for_vuln_mode(deps, challenge_dirs)

    mcp_server = _build_vuln_coordinator_mcp(deps)

    allowed = {
        "mcp__vuln_coordinator__list_vulnerabilities",
        "mcp__vuln_coordinator__get_investigation_status",
        "mcp__vuln_coordinator__spawn_investigator",
        "mcp__vuln_coordinator__check_investigator_status",
        "mcp__vuln_coordinator__read_investigator_trace",
        "mcp__vuln_coordinator__bump_investigator",
        "mcp__vuln_coordinator__kill_investigator",
        "ToolSearch",
        "TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TaskOutput", "TaskStop",
    }

    async def enforce_allowlist(input_data, tool_use_id, context):
        if input_data.get("hook_event_name") != "PreToolUse":
            return {}
        tool_name = input_data.get("tool_name", "")
        if tool_name in allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"{tool_name} not available to vuln coordinator.",
            }
        }

    options = ClaudeAgentOptions(
        model=coordinator_model,
        system_prompt=VULN_COORDINATOR_PROMPT,
        env={"CLAUDECODE": ""},
        mcp_servers={"vuln_coordinator": mcp_server},
        allowed_tools=list(allowed),
        permission_mode="bypassPermissions",
        hooks={"PreToolUse": [HookMatcher(hooks=[enforce_allowlist])]},
    )

    async with ClaudeSDKClient(options=options) as client:
        async def turn_fn(msg: str) -> None:
            logger.debug("Vuln coordinator query: %s", msg[:200])
            await client.query(msg)
            async for message in client.receive_response():
                if isinstance(message, ResultMessage):
                    cost = getattr(message, "total_cost_usd", 0)
                    logger.info("Coordinator turn done (cost=$%.4f)", cost)

        return await run_vuln_event_loop(deps, turn_fn, trivy_summary)


def _patch_swarm_for_vuln_mode(deps: CoordinatorDeps, challenge_dirs: dict[str, str]) -> None:
    """Patch the swarm factory to inject vuln-specific prompts and output schemas.

    This function temporarily monkey-patches ``do_spawn_swarm`` in
    ``coordinator_core`` so that each spawned swarm uses ``VulnChallengeSwarm``
    instead of the default ``ChallengeSwarm``.  The original class is restored
    inside a ``finally`` block on every call, so the patch is never permanent.

    Trade-off: this approach avoids adding a swarm-factory parameter throughout
    the coordinator stack (a more invasive refactor), at the cost of making the
    relationship between ``vuln_coordinator`` and ``coordinator_core`` implicit.
    A future refactor could pass a ``swarm_factory`` callable to
    ``CoordinatorDeps`` or ``do_spawn_swarm`` instead.
    """
    from backend.agents import swarm as swarm_module
    base_swarm_cls = swarm_module.ChallengeSwarm

    class VulnChallengeSwarm(base_swarm_cls):
        """ChallengeSwarm variant that injects vuln investigator prompts."""

        def _create_solver(self, model_spec: str):
            from backend.agents.claude_solver import ClaudeSolver
            from backend.models import provider_from_spec
            from backend.output_types import vuln_output_json_schema
            from backend.vuln_prompts import build_investigator_prompt_from_dir

            provider = provider_from_spec(model_spec)
            if provider == "claude-sdk":
                system_prompt = build_investigator_prompt_from_dir(self.challenge_dir)
                output_schema = vuln_output_json_schema()
                return ClaudeSolver(
                    model_spec=model_spec,
                    challenge_dir=self.challenge_dir,
                    meta=self.meta,
                    ctfd=self.ctfd,
                    cost_tracker=self.cost_tracker,
                    settings=self.settings,
                    cancel_event=self.cancel_event,
                    no_submit=self.no_submit,
                    submit_fn=lambda flag: self.try_submit_flag(flag, model_spec),
                    message_bus=self.message_bus,
                    notify_coordinator=self._make_notify_fn(model_spec),
                    system_prompt_override=system_prompt,
                    output_schema=output_schema,
                )
            # Fallback to standard solver for non-claude-sdk models
            return super()._create_solver(model_spec)

    # Replace reference so do_spawn_swarm creates VulnChallengeSwarm
    import backend.agents.coordinator_core as core_module
    _orig_spawn = core_module.do_spawn_swarm

    async def _patched_spawn_swarm(deps_inner, challenge_name: str) -> str:
        """Wrapper that substitutes VulnChallengeSwarm for ChallengeSwarm."""
        import backend.agents.swarm as swarm_mod
        _orig_cls = swarm_mod.ChallengeSwarm
        swarm_mod.ChallengeSwarm = VulnChallengeSwarm
        try:
            return await _orig_spawn(deps_inner, challenge_name)
        finally:
            swarm_mod.ChallengeSwarm = _orig_cls

    core_module.do_spawn_swarm = _patched_spawn_swarm  # type: ignore[assignment]
