# Person C owns this file. See WORKPLAN.md §4 for the exact contract.


def build_report(findings: list[dict], fix_list: list[dict], meta: dict) -> dict:
    """meta = {"target": str, "timestamp": str, "transport": "docker"}.
    Returns the report.json structure: findings, fix_list, unknowns
    (findings with status UNKNOWN, listed separately, not silently dropped),
    and a summary count of PASS/FAIL/UNKNOWN.

    This is also the exact JSON the React UI (ui/) reads — do not change
    this shape without updating ui/src alongside it."""
    raise NotImplementedError


def render_markdown(report: dict) -> str:
    """Human-readable report.md: summary counts at top, then fix list in
    priority order, then full findings table, then UNKNOWNs with reasons."""
    raise NotImplementedError
