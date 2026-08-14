"""Unit tests for collector.classify(). Run with `pytest` if installed,
otherwise `python tests/test_collector.py` runs the same checks directly —
no dependency required, since a hackathon shouldn't block on pip installs.

The strings below are not invented — they were captured live from
`docker exec -u audituser cis-broken ...` against targets/Dockerfile.broken
while building this pipeline (see WORKPLAN.md §4 footnote).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_agent.collector import classify

# This docker version writes the OCI failure to STDOUT, confirmed via
# `python3 -c "import subprocess; print(subprocess.run([...], capture_output=True, text=True))"`
# against a live container — NOT stderr, which is why classify() checks both
# streams rather than assuming one.
REAL_BINARY_NOT_FOUND_STDOUT = (
    'OCI runtime exec failed: exec failed: unable to start container process: '
    'exec: "iptables": executable file not found in $PATH\n'
)
REAL_PERMISSION_DENIED_STDERR = "awk: cannot open /etc/shadow (Permission denied)"


def test_timeout_beats_everything_else():
    status, reason = classify(None, "", "", timed_out=True)
    assert status == "unavailable"
    assert reason == "timed out"


def test_missing_binary_message_in_stdout():
    # the real, observed case — see the module docstring
    status, reason = classify(127, REAL_BINARY_NOT_FOUND_STDOUT, "", timed_out=False)
    assert status == "unavailable"
    assert reason == "binary not found in container"


def test_missing_binary_message_in_stderr_also_detected():
    # not observed on this docker version, but a different one might behave
    # differently — classify() must not assume a fixed stream
    status, reason = classify(127, "", REAL_BINARY_NOT_FOUND_STDOUT, timed_out=False)
    assert status == "unavailable"
    assert reason == "binary not found in container"


def test_permission_denied():
    status, reason = classify(2, "", REAL_PERMISSION_DENIED_STDERR, timed_out=False)
    assert status == "unavailable"
    assert reason == "permission denied"


def test_nonzero_exit_with_no_match_is_ok_not_unavailable():
    # grep exits 1 when it finds nothing — that IS the PASS evidence for
    # CIS-5.2.9, not a transport failure.
    status, reason = classify(1, "", "", timed_out=False)
    assert status == "ok"
    assert reason is None


def test_missing_config_file_is_ok_not_unavailable():
    # cat reporting a config file doesn't exist is FAIL evidence for
    # CIS-2.2.4 (auto-updates not configured), not an unavailable command —
    # see WORKPLAN.md §3 footnote for why this is deliberately NOT
    # pattern-matched the same way as a missing binary.
    stderr = "cat: /etc/apt/apt.conf.d/20auto-upgrades: No such file or directory"
    status, reason = classify(1, "", stderr, timed_out=False)
    assert status == "ok"
    assert reason is None


def test_clean_success_is_ok():
    status, reason = classify(0, "permitrootlogin no\n", "", timed_out=False)
    assert status == "ok"
    assert reason is None


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
