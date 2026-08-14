"""collector.py — runs the fixed allowlisted commands against an open
session and classifies each result per the capture contract (WORKPLAN.md
§2.1). Never raises on a single command's failure; only
connector.open_session() failures are fatal (Requirement 9).
"""

from __future__ import annotations

import json
from pathlib import Path

from . import allowlist


def classify(returncode, stdout: str, stderr: str, timed_out: bool):
    """Pure function — no Docker, no I/O. Returns (status, reason) where
    status is "ok" or "unavailable" (§2.1). Checked in this order — see
    WORKPLAN.md §4 Person A for why the order matters:

    1. timed_out                                        -> unavailable, "timed out"
    2. docker couldn't start the process (binary missing) -> unavailable, "binary not found in container"
    3. process started but couldn't read something        -> unavailable, "permission denied"
    4. anything else, regardless of exit code             -> ok, None
       (covers real PASS evidence AND real FAIL evidence — e.g. grep exiting
       1 because it found nothing, or `cat` reporting "No such file or
       directory" for a config file that's legitimately absent)
    """
    if timed_out:
        return "unavailable", "timed out"

    # Checked against BOTH streams, not just stderr: verified live that this
    # docker version writes "OCI runtime exec failed" to stdout, not stderr
    # (confirmed via `docker exec -u audituser cis-broken iptables ...` —
    # see WORKPLAN.md §4 footnote). Trusting a single stream here would have
    # silently misclassified the missing-binary case as "ok".
    combined = (stdout + stderr).lower()
    if "executable file not found" in combined or "oci runtime exec failed" in combined:
        return "unavailable", "binary not found in container"
    if "permission denied" in combined:
        return "unavailable", "permission denied"

    return "ok", None


def run_all(session, os_family: str = "linux", debug_dump_path: str | None = "debug_raw_output.json") -> list[dict]:
    """Runs every command in allowlist.COMMANDS[os_family] through `session`,
    classifies each result, and returns a list of capture dicts (§2.1
    contract). Order matches allowlist.COMMANDS[os_family] exactly — that
    fixed order is part of what keeps downstream output deterministic
    (WORKPLAN.md §5 no-drift). os_family defaults to "linux"; cli.py never
    passes anything else this hackathon (WORKPLAN.md §0)."""
    captures = []
    for entry in allowlist.COMMANDS[os_family]:
        result = session.run(entry["argv"])
        status, reason = classify(
            result["exit_code"], result["stdout"], result["stderr"], result["timed_out"]
        )
        captures.append(
            {
                "command_id": entry["command_id"],
                "os_family": os_family,
                "argv": entry["argv"],
                "exit_code": result["exit_code"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "status": status,
                "reason": reason,
            }
        )

    if debug_dump_path:
        Path(debug_dump_path).write_text(json.dumps(captures, indent=2))

    return captures
