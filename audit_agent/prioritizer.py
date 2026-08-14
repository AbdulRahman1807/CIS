# Person C owns this file. See WORKPLAN.md §4 for the exact contract.
#
# Build against audit_agent/fixtures/sample_findings.json (hand-write that
# fixture first — 10 items, shape from WORKPLAN.md §2.2 — so this doesn't
# wait on Person A or B).

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

REMEDIATION_TEMPLATES = {
    # "CIS-5.2.10": {
    #     "category": "SSH hardening",
    #     "why_it_matters": "...",
    #     "fix_command": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
    # },
    # ... one entry per rule_id in WORKPLAN.md §3.
}


def prioritize(findings: list[dict]) -> list[dict]:
    """Filters to status == "FAIL" only. Looks up each in
    REMEDIATION_TEMPLATES. Sorts by (SEVERITY_ORDER[severity_hint], rule_id)
    — rule_id as tiebreak is what makes ordering deterministic across runs.
    Assigns priority = 1..N after sorting. Every item's evidence_ref == its
    rule_id."""
    raise NotImplementedError
