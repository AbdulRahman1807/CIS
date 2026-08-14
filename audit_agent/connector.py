"""connector.py — opens a read-only docker exec session against a target
container. Every command runs as `audituser` (WORKPLAN.md §0), never root.
Nothing here builds a command by string interpolation; argv is always a
literal list, both here and in every caller.
"""

from __future__ import annotations

import subprocess

AUDIT_USER = "audituser"


class ConnectorError(Exception):
    """No session could be established at all. Fatal — the caller (cli.py)
    must exit non-zero and run nothing else (Requirement 9)."""


class DockerSession:
    def __init__(self, target: str):
        self.target = target

    def run(self, argv: list[str], timeout: int = 5) -> dict:
        """Runs `docker exec -u audituser <target> <argv...>`. Never raises
        on a command-level failure — that's collector.classify()'s job.
        Returns {"exit_code": int | None, "stdout": str, "stderr": str,
        "timed_out": bool}. exit_code is None only when timed_out is True."""
        try:
            proc = subprocess.run(
                ["docker", "exec", "-u", AUDIT_USER, self.target, *argv],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            def _decode(x):
                if x is None:
                    return ""
                return x.decode(errors="replace") if isinstance(x, bytes) else x

            return {
                "exit_code": None,
                "stdout": _decode(exc.stdout),
                "stderr": _decode(exc.stderr),
                "timed_out": True,
            }


def open_session(target: str) -> DockerSession:
    """Verifies `docker exec -u audituser <target> true` succeeds. Raises
    ConnectorError if the container doesn't exist, isn't running, or
    audituser doesn't exist inside it. Never falls back to a default target
    or to root — a broken connection must fail loudly (Requirement 9)."""
    try:
        proc = subprocess.run(
            ["docker", "exec", "-u", AUDIT_USER, target, "true"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise ConnectorError("docker binary not found on PATH") from None
    except subprocess.TimeoutExpired:
        raise ConnectorError(f"timed out opening a session against {target!r}") from None

    if proc.returncode != 0:
        raise ConnectorError(
            f"could not open a read-only session against {target!r}: {proc.stderr.strip()}"
        )
    return DockerSession(target)
