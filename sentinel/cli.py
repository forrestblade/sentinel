"""Sentinel CLI for managing the tool gating and receipt system."""

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import click

from sentinel.config import load_config
from sentinel.crypto import generate_keypair, load_private_key, load_public_key
from sentinel.receipt import ReceiptChain

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "sentinel"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "sentinel.yaml"
DEFAULT_DATA_DIR = DEFAULT_CONFIG_DIR / "data"


def _is_process_running(pid: int) -> bool:
    """Return True if pid appears to be alive on POSIX or Windows."""
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _terminate_process(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.kill(pid, signal.SIGTERM)


EXAMPLE_CONFIG = """\
server:
  host: "127.0.0.1"
  port: 9800
  data_dir: "~/.config/sentinel/data"

fsm:
  initial_state: "idle"

  states:
    idle:
      description: "No active workflow"
      allowed_tools: [".*"]

    planning:
      description: "Read-only exploration"
      allowed_tools: ["read", "bash", "multi_tool_use\\\\.parallel"]

    developing:
      description: "Full tool access"
      allowed_tools: [".*"]

    testing:
      description: "Test execution only"
      allowed_tools: ["read", "bash", "multi_tool_use\\\\.parallel"]

    reviewing:
      description: "Read-only review"
      allowed_tools: ["read", "bash", "multi_tool_use\\\\.parallel"]

  transitions:
    - { from: idle, to: planning, trigger: manual }
    - { from: idle, to: developing, trigger: manual }
    - { from: planning, to: developing, trigger: manual }
    - from: developing
      to: testing
      trigger: bash
      guards:
        - field: command
          pattern: "^(pnpm|npm)\\\\s+test"
    - { from: testing, to: developing, trigger: manual }
    - { from: developing, to: reviewing, trigger: manual }
    - { from: reviewing, to: developing, trigger: manual }
    - { from: "*", to: idle, trigger: manual }
"""


@click.group()
@click.option("--config", "config_path", type=click.Path(path_type=Path),
              default=DEFAULT_CONFIG_PATH, help="Path to sentinel.yaml")
@click.pass_context
def cli(ctx: click.Context, config_path: Path) -> None:
    """Sentinel: State-based tool gating & cryptographic receipts for pi."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


@cli.command()
@click.option("--data-dir", type=click.Path(path_type=Path), default=DEFAULT_DATA_DIR)
@click.pass_context
def init(ctx: click.Context, data_dir: Path) -> None:
    """Initialize sentinel: generate keys, create config."""
    config_path = ctx.obj["config_path"]

    # Create config directory
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Write example config if it doesn't exist
    if not config_path.exists():
        config_path.write_text(EXAMPLE_CONFIG)
        click.echo(f"Created config: {config_path}")
    else:
        click.echo(f"Config already exists: {config_path}")

    # Generate keys
    key_dir = data_dir / "keys"
    if (key_dir / "sentinel.key").exists():
        click.echo(f"Keys already exist: {key_dir}")
    else:
        generate_keypair(key_dir)
        click.echo(f"Generated Ed25519 keypair: {key_dir}")

    # Create data directory
    data_dir.mkdir(parents=True, exist_ok=True)
    click.echo(f"Data directory: {data_dir}")
    click.echo("\nSentinel initialized. Run 'sentinel start' to begin.")


@cli.command()
@click.option("--host", default=None)
@click.option("--port", type=int, default=None)
@click.option("--daemon", is_flag=True, help="Run in background")
@click.pass_context
def start(ctx: click.Context, host: str | None, port: int | None, daemon: bool) -> None:
    """Start the sentinel HTTP server."""
    config_path = ctx.obj["config_path"]
    if not config_path.exists():
        click.echo(f"Config not found: {config_path}\nRun 'sentinel init' first.", err=True)
        sys.exit(1)

    config = load_config(config_path)
    pid_path = config.server.data_dir / "sentinel.pid"

    if pid_path.exists():
        pid = int(pid_path.read_text().strip())
        if _is_process_running(pid):
            click.echo(f"Sentinel already running (PID {pid})", err=True)
            sys.exit(1)
        pid_path.unlink()

    if daemon:
        h = host or config.server.host
        p = port or config.server.port
        proc = subprocess.Popen(
            [sys.executable, "-m", "sentinel.cli", "--config", str(config_path), "start",
             "--host", h, "--port", str(p)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        click.echo(f"Sentinel started in background (PID {proc.pid}) on {h}:{p}")
    else:
        from sentinel.server import run_server
        run_server(config_path, host, port)


@cli.command()
@click.pass_context
def stop(ctx: click.Context) -> None:
    """Stop the running sentinel server."""
    config_path = ctx.obj["config_path"]
    if not config_path.exists():
        click.echo("Config not found.", err=True)
        sys.exit(1)

    config = load_config(config_path)
    pid_path = config.server.data_dir / "sentinel.pid"

    if not pid_path.exists():
        click.echo("Sentinel is not running (no PID file).")
        return

    pid = int(pid_path.read_text().strip())
    try:
        _terminate_process(pid)
        click.echo(f"Sentinel stopped (PID {pid}).")
    except (ProcessLookupError, subprocess.CalledProcessError):
        click.echo("Sentinel was not running (stale PID file).")
    finally:
        if pid_path.exists():
            pid_path.unlink()


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show sentinel status: server, FSM state, chain length."""
    config_path = ctx.obj["config_path"]
    if not config_path.exists():
        click.echo("Not initialized. Run 'sentinel init'.", err=True)
        sys.exit(1)

    config = load_config(config_path)
    data_dir = config.server.data_dir

    # Server status
    pid_path = data_dir / "sentinel.pid"
    if pid_path.exists():
        pid = int(pid_path.read_text().strip())
        if _is_process_running(pid):
            click.echo(f"Server: running (PID {pid}) on {config.server.host}:{config.server.port}")
        else:
            click.echo("Server: not running (stale PID)")
    else:
        click.echo("Server: not running")

    # FSM state
    state_path = data_dir / "state.json"
    if state_path.exists():
        state = json.loads(state_path.read_text())
        click.echo(f"State:  {state['current']}")
        if state.get("previous"):
            click.echo(f"  Previous: {state['previous']}")
        click.echo(f"  Transitions: {state['transition_count']}")
    else:
        click.echo("State:  not initialized")

    # Chain
    chain_path = data_dir / "receipts.jsonl"
    if chain_path.exists():
        count = sum(1 for line in open(chain_path) if line.strip())
        click.echo(f"Chain:  {count} receipts")
    else:
        click.echo("Chain:  empty")


@cli.command()
@click.pass_context
def state(ctx: click.Context) -> None:
    """Show detailed FSM state info."""
    config_path = ctx.obj["config_path"]
    config = load_config(config_path)

    state_path = config.server.data_dir / "state.json"
    if not state_path.exists():
        click.echo("FSM not initialized.")
        return

    fsm_state = json.loads(state_path.read_text())
    state_config = config.fsm.states.get(fsm_state["current"])

    click.echo(f"Current state: {fsm_state['current']}")
    if state_config:
        click.echo(f"Description:   {state_config.description}")
        click.echo(f"Allowed tools: {', '.join(state_config.allowed_tools)}")
    click.echo(f"Previous:      {fsm_state.get('previous', 'None')}")
    click.echo(f"Transitions:   {fsm_state['transition_count']}")

    # Show available transitions
    current = fsm_state["current"]
    available = [t for t in config.fsm.transitions
                 if t.from_state == "*" or t.from_state == current]
    if available:
        click.echo("\nAvailable transitions:")
        for t in available:
            guard_info = ""
            if t.guards:
                guard_info = f" (guards: {', '.join(g.field + '~' + g.pattern for g in t.guards)})"
            click.echo(f"  -> {t.to_state} [trigger: {t.trigger}]{guard_info}")


@cli.command()
@click.argument("state_name")
@click.option("--reason", default="", help="Reason for transition")
@click.pass_context
def transition(ctx: click.Context, state_name: str, reason: str) -> None:
    """Manually transition to a new state."""
    import urllib.request

    config_path = ctx.obj["config_path"]
    config = load_config(config_path)

    url = f"http://{config.server.host}:{config.server.port}/transition"
    payload = json.dumps({"to_state": state_name, "reason": reason}).encode()

    try:
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            click.echo(f"{data['previous']} -> {data['current']}")
    except Exception as e:
        click.echo(f"Failed to transition (is server running?): {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def verify(ctx: click.Context) -> None:
    """Verify the receipt chain integrity."""
    config_path = ctx.obj["config_path"]
    config = load_config(config_path)
    data_dir = config.server.data_dir

    chain_path = data_dir / "receipts.jsonl"
    if not chain_path.exists():
        click.echo("No receipt chain found.")
        return

    key_dir = data_dir / "keys"
    private_key = load_private_key(key_dir / "sentinel.key")
    public_key = load_public_key(key_dir / "sentinel.pub")

    chain = ReceiptChain(chain_path, private_key, public_key)
    valid, last_seq, msg = chain.verify_chain()

    if valid:
        click.echo(f"Chain valid: {chain.length} receipts verified")
    else:
        click.echo(f"CHAIN BROKEN at seq {last_seq + 1}: {msg}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--tool", "tool_name", default=None, help="Filter by tool name")
@click.option("--state", "state_filter", default=None, help="Filter by state")
@click.option("--event", default=None, help="Filter by event type")
@click.option("--limit", "-n", default=20, help="Number of receipts to show")
@click.pass_context
def audit(ctx: click.Context, tool_name: str | None, state_filter: str | None,
          event: str | None, limit: int) -> None:
    """View the receipt audit trail."""
    config_path = ctx.obj["config_path"]
    config = load_config(config_path)
    data_dir = config.server.data_dir

    chain_path = data_dir / "receipts.jsonl"
    if not chain_path.exists():
        click.echo("No receipts.")
        return

    key_dir = data_dir / "keys"
    private_key = load_private_key(key_dir / "sentinel.key")
    public_key = load_public_key(key_dir / "sentinel.pub")

    chain = ReceiptChain(chain_path, private_key, public_key)
    receipts = chain.get_receipts(tool_name=tool_name, state=state_filter, event=event, limit=limit)

    if not receipts:
        click.echo("No matching receipts.")
        return

    for r in receipts:
        sig_short = r.signature[:12] + "..."
        click.echo(
            f"[{r.seq:04d}] {r.id}  {r.event:<14} "
            f"{r.tool_name:<20} state={r.state:<12} sig={sig_short}"
        )


if __name__ == "__main__":
    cli()
