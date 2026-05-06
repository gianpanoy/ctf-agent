"""Click CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console

from backend.config import Settings
from backend.models import DEFAULT_MODELS

console = Console()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("aiodocker").setLevel(logging.WARNING)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%X"))
    logging.basicConfig(level=level, handlers=[handler], force=True)


@click.command()
@click.option("--ctfd-url", default=None, help="CTFd URL (overrides .env)")
@click.option("--ctfd-token", default=None, help="CTFd API token (overrides .env)")
@click.option("--image", default="ctf-sandbox", help="Docker sandbox image name")
@click.option("--models", multiple=True, help="Model specs (default: all configured)")
@click.option("--challenge", default=None, help="Solve a single challenge directory")
@click.option("--challenges-dir", default="challenges", help="Directory for challenge files")
@click.option("--no-submit", is_flag=True, help="Dry run — don't submit flags")
@click.option("--coordinator-model", default=None, help="Model for coordinator (default: claude-opus-4-6)")
@click.option("--coordinator", default="claude", type=click.Choice(["claude", "codex"]), help="Coordinator backend")
@click.option("--max-challenges", default=10, type=int, help="Max challenges solved concurrently")
@click.option("--msg-port", default=0, type=int, help="Operator message port (0 = auto)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(
    ctfd_url: str | None,
    ctfd_token: str | None,
    image: str,
    models: tuple[str, ...],
    challenge: str | None,
    challenges_dir: str,
    no_submit: bool,
    coordinator_model: str | None,
    coordinator: str,
    max_challenges: int,
    msg_port: int,
    verbose: bool,
) -> None:
    """CTF Agent — multi-model solver swarm.

    Run without --challenge to start the full coordinator (Ctrl+C to stop).
    """
    _setup_logging(verbose)

    settings = Settings(sandbox_image=image)
    if ctfd_url:
        settings.ctfd_url = ctfd_url
    if ctfd_token:
        settings.ctfd_token = ctfd_token
    settings.max_concurrent_challenges = max_challenges

    model_specs = list(models) if models else list(DEFAULT_MODELS)

    console.print("[bold]CTF Agent v2[/bold]")
    console.print(f"  CTFd: {settings.ctfd_url}")
    console.print(f"  Models: {', '.join(model_specs)}")
    console.print(f"  Image: {settings.sandbox_image}")
    console.print(f"  Max challenges: {max_challenges}")
    console.print()

    if challenge:
        asyncio.run(_run_single(settings, challenge, model_specs, no_submit, max_challenges))
    else:
        asyncio.run(_run_coordinator(settings, model_specs, challenges_dir, no_submit, coordinator_model, coordinator, max_challenges, msg_port))


@click.command()
@click.option("--targets-file", default=None, help="YAML file listing repos to scan")
@click.option("--target", default=None, help="Single repo URL or local path to scan")
@click.option("--models", multiple=True, help="Investigator model specs (default: all configured)")
@click.option("--coordinator-model", default="claude-opus-4-6", show_default=True, help="Coordinator model")
@click.option(
    "--severity", default="HIGH", show_default=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    help="Minimum severity to investigate",
)
@click.option("--max-findings", default=5, show_default=True, type=int,
              help="Max findings to investigate per target")
@click.option("--output-dir", default="vuln-reports", show_default=True,
              help="Directory to write reports")
@click.option("--image", default="ctf-sandbox", show_default=True, help="Docker sandbox image")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def vuln_scan(
    targets_file: str | None,
    target: str | None,
    models: tuple[str, ...],
    coordinator_model: str,
    severity: str,
    max_findings: int,
    output_dir: str,
    image: str,
    verbose: bool,
) -> None:
    """Vulnerability finder — scan open-source repos with Trivy then investigate with AI.

    Provide either --targets-file (YAML list of repos) or --target (single repo URL).

    Example targets.yml:

    \b
        targets:
          - name: my-project
            url: https://github.com/org/repo

    The tool runs Trivy repo scans, filters CRITICAL/HIGH findings, then spawns AI
    investigator agents to produce a detailed vulnerability analysis report.
    """
    _setup_logging(verbose)

    if not targets_file and not target:
        console.print("[red]Error:[/red] Provide --targets-file or --target")
        raise SystemExit(1)

    settings = Settings(
        sandbox_image=image,
        trivy_severity=severity.upper(),
        max_vuln_findings=max_findings,
        report_output_dir=output_dir,
    )

    model_specs = list(models) if models else list(DEFAULT_MODELS)

    console.print("[bold]CTF Agent — Vulnerability Finder[/bold]")
    console.print(f"  Severity threshold: {severity.upper()}")
    console.print(f"  Max findings/target: {max_findings}")
    console.print(f"  Models: {', '.join(model_specs)}")
    console.print(f"  Output: {output_dir}")
    console.print()

    asyncio.run(
        _run_vuln_scan(
            settings=settings,
            targets_file=targets_file,
            single_target=target,
            model_specs=model_specs,
            coordinator_model=coordinator_model,
        )
    )


async def _run_single(
    settings: Settings,
    challenge_dir: str,
    model_specs: list[str],
    no_submit: bool,
    max_challenges: int,
) -> None:
    """Run a single challenge with a swarm."""
    from backend.agents.swarm import ChallengeSwarm
    from backend.cost_tracker import CostTracker
    from backend.ctfd import CTFdClient
    from backend.prompts import ChallengeMeta
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore

    max_containers = max_challenges * len(model_specs)
    configure_semaphore(max_containers)
    await cleanup_orphan_containers()

    challenge_path = Path(challenge_dir)
    meta_path = challenge_path / "metadata.yml"
    if not meta_path.exists():
        console.print(f"[red]No metadata.yml found in {challenge_dir}[/red]")
        sys.exit(1)

    meta = ChallengeMeta.from_yaml(meta_path)
    console.print(f"[bold]Challenge:[/bold] {meta.name} ({meta.category}, {meta.value} pts)")

    ctfd = CTFdClient(
        base_url=settings.ctfd_url,
        token=settings.ctfd_token,
        username=settings.ctfd_user,
        password=settings.ctfd_pass,
    )
    cost_tracker = CostTracker()

    swarm = ChallengeSwarm(
        challenge_dir=str(challenge_path),
        meta=meta,
        ctfd=ctfd,
        cost_tracker=cost_tracker,
        settings=settings,
        model_specs=model_specs,
        no_submit=no_submit,
    )

    try:
        result = await swarm.run()
        from backend.solver_base import FLAG_FOUND
        if result and result.status == FLAG_FOUND:
            console.print(f"\n[bold green]FLAG FOUND:[/bold green] {result.flag}")
        else:
            console.print("\n[bold red]No flag found.[/bold red]")

        console.print("\n[bold]Cost Summary:[/bold]")
        for agent_name in cost_tracker.by_agent:
            console.print(f"  {agent_name}: {cost_tracker.format_usage(agent_name)}")
        console.print(f"  [bold]Total: ${cost_tracker.total_cost_usd:.2f}[/bold]")
    finally:
        await ctfd.close()


async def _run_coordinator(
    settings: Settings,
    model_specs: list[str],
    challenges_dir: str,
    no_submit: bool,
    coordinator_model: str | None,
    coordinator_backend: str,
    max_challenges: int,
    msg_port: int = 0,
) -> None:
    """Run the full coordinator (continuous until Ctrl+C)."""
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore

    max_containers = max_challenges * len(model_specs)
    configure_semaphore(max_containers)
    await cleanup_orphan_containers()
    console.print(f"[bold]Starting coordinator ({coordinator_backend}, Ctrl+C to stop)...[/bold]\n")

    if coordinator_backend == "codex":
        from backend.agents.codex_coordinator import run_codex_coordinator
        results = await run_codex_coordinator(
            settings=settings,
            model_specs=model_specs,
            challenges_root=challenges_dir,
            no_submit=no_submit,
            coordinator_model=coordinator_model,
            msg_port=msg_port,
        )
    else:
        from backend.agents.claude_coordinator import run_claude_coordinator
        results = await run_claude_coordinator(
            settings=settings,
            model_specs=model_specs,
            challenges_root=challenges_dir,
            no_submit=no_submit,
            coordinator_model=coordinator_model,
            msg_port=msg_port,
        )

    console.print("\n[bold]Final Results:[/bold]")
    for challenge, data in results.get("results", {}).items():
        console.print(f"  {challenge}: {data.get('flag', 'no flag')}")
    console.print(f"\n[bold]Total cost: ${results.get('total_cost_usd', 0):.2f}[/bold]")


async def _run_vuln_scan(
    settings: Settings,
    targets_file: str | None,
    single_target: str | None,
    model_specs: list[str],
    coordinator_model: str,
) -> None:
    """Run the full vulnerability scanning pipeline."""
    from backend.agents.vuln_coordinator import run_vuln_coordinator
    from backend.prompts import ChallengeMeta
    from backend.reporter import write_reports
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.target import TargetMeta, create_vuln_challenge_dirs, load_targets
    from backend.trivy import trivy_scan

    configure_semaphore(len(model_specs) * settings.max_vuln_findings)
    await cleanup_orphan_containers()

    # 1. Load targets
    if targets_file:
        targets = load_targets(targets_file)
    else:
        assert single_target
        name = single_target.rstrip("/").split("/")[-1] or "target"
        targets = [TargetMeta(name=name, url=single_target)]

    console.print(f"[bold]Scanning {len(targets)} target(s) with Trivy...[/bold]")

    # 2. Run Trivy on each target (sequentially to avoid overloading)
    all_challenge_dirs: dict[str, str] = {}
    all_challenge_metas: dict[str, ChallengeMeta] = {}
    all_scan_summaries: list[str] = []
    scan_target_urls: list[str] = []

    # Use the first (most severe) threshold from the comma-separated severity list
    min_severity = settings.trivy_severity.split(",")[0].strip().upper() or "HIGH"

    for target in targets:
        console.print(f"  Trivy scanning: [cyan]{target.url}[/cyan]")
        scan_result = await trivy_scan(target.url, severity=settings.trivy_severity)

        if scan_result.error:
            console.print(f"  [yellow]Warning:[/yellow] Trivy error for {target.name}: {scan_result.error}")
            continue

        total = len(scan_result.findings)
        console.print(
            f"  Found [bold]{total}[/bold] finding(s) "
            f"(CRITICAL: {scan_result.critical_count}, HIGH: {scan_result.high_count})"
        )

        if not scan_result.findings:
            continue

        # 3. Create challenge dirs from top findings
        ch_dirs = create_vuln_challenge_dirs(
            scan_result,
            target,
            output_root=str(Path(settings.report_output_dir) / "challenges"),
            max_findings=settings.max_vuln_findings,
            min_severity=min_severity,
        )
        all_challenge_dirs.update(ch_dirs)
        all_scan_summaries.append(scan_result.format_summary(max_findings=settings.max_vuln_findings))
        scan_target_urls.append(target.url)

        for ch_name, ch_dir in ch_dirs.items():
            meta = ChallengeMeta.from_yaml(Path(ch_dir) / "metadata.yml")
            all_challenge_metas[ch_name] = meta

    if not all_challenge_dirs:
        console.print("\n[green]No qualifying vulnerabilities found. Nothing to investigate.[/green]")
        return

    console.print(
        f"\n[bold]Investigating [green]{len(all_challenge_dirs)}[/green] "
        f"vulnerability finding(s) with {len(model_specs)} model(s)...[/bold]\n"
    )

    trivy_summary = "\n\n---\n\n".join(all_scan_summaries)

    # 4. Run the vuln coordinator
    results = await run_vuln_coordinator(
        settings=settings,
        challenge_dirs=all_challenge_dirs,
        challenge_metas=all_challenge_metas,
        trivy_summary=trivy_summary,
        model_specs=model_specs,
        coordinator_model=coordinator_model,
        report_output_dir=settings.report_output_dir,
    )

    # 5. Write reports
    json_path, md_path = write_reports(
        results.get("results", {}),
        output_dir=settings.report_output_dir,
        scan_targets=scan_target_urls,
    )

    console.print("\n[bold green]Vulnerability analysis complete![/bold green]")
    console.print(f"  JSON report : {json_path}")
    console.print(f"  Markdown    : {md_path}")
    console.print(f"  Total cost  : ${results.get('total_cost_usd', 0):.2f}")


@click.command()
@click.argument("message")
@click.option("--port", default=9400, type=int, help="Coordinator message port")
@click.option("--host", default="127.0.0.1", help="Coordinator host")
def msg(message: str, port: int, host: str) -> None:
    """Send a message to the running coordinator."""
    import json
    import urllib.request

    body = json.dumps({"message": message}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/msg",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            console.print(f"[green]Sent:[/green] {data.get('queued', message[:200])}")
    except Exception as e:
        console.print(f"[red]Failed:[/red] {e}")
        console.print("Is the coordinator running?")
        sys.exit(1)


if __name__ == "__main__":
    main()
