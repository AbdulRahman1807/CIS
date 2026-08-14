# Person B owns this file. See WORKPLAN.md §3 for the locked list of 10
# rules and §4 for this module's exact contract.
#
# Build against audit_agent/fixtures/sample_captures.json (Person A's
# fixture — not present yet since A is still building the real collector).
# Once A's real collector output exists, swap the fixture for the real thing.

RULES = [
    # {
    #     "rule_id": "CIS-5.2.10",
    #     "title": "SSH root login disabled",
    #     "command_id": "cmd_sshd_config",
    #     "severity_hint": "high",
    #     "parse": lambda stdout: ...,  # returns ("PASS" | "FAIL", evidence)
    # },
    # ... all 10 from WORKPLAN.md §3. rule_id and command_id must match
    # Person A's allowlist.py exactly.
]


def evaluate(captures: list[dict]) -> list[dict]:
    """captures = collector.run_all() output (WORKPLAN.md §2.1 contract).
    Returns list of Finding dicts (§2.2 contract), one per rule in RULES,
    in RULES order (this fixed order feeds the no-drift sort in §6).
    If the capture for a rule's command_id has status != "ok", the finding
    is UNKNOWN with evidence = the capture's stderr/reason. Never invent a
    PASS/FAIL when the underlying capture wasn't captured cleanly."""
    raise NotImplementedError
