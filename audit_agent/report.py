"""report.py — assembles the final report.json / report.md
(WORKPLAN.md §4 Person C). This JSON shape is also exactly what
audit_agent/webui.py + audit_agent/templates/report.html and ui/src/App.jsx
read — do not change field names here without updating those too.
"""

from __future__ import annotations


def build_report(findings: list[dict], fix_list: list[dict], meta: dict) -> dict:
    """meta = {"target": str, "timestamp": str, "transport": "docker"}.
    Returns findings, fix_list, unknowns (UNKNOWN findings, listed
    separately — never silently dropped), and a PASS/FAIL/UNKNOWN summary
    count."""
    passes = sum(1 for f in findings if f["status"] == "PASS")
    fails = sum(1 for f in findings if f["status"] == "FAIL")
    unknowns = [f for f in findings if f["status"] == "UNKNOWN"]
    return {
        "meta": meta,
        "summary": {"pass": passes, "fail": fails, "unknown": len(unknowns)},
        "findings": findings,
        "fix_list": fix_list,
        "unknowns": unknowns,
    }


def render_markdown(report: dict) -> str:
    """Human-readable report.md: summary counts, then fix list in priority
    order, then the full findings table, then UNKNOWNs with reasons."""
    lines = []
    meta = report["meta"]
    lines.append(f"# CIS Audit Report — {meta['target']}")
    lines.append("")
    lines.append(f"Generated: {meta['timestamp']} via {meta['transport']}")
    lines.append("")

    s = report["summary"]
    lines.append(f"**Summary:** {s['pass']} PASS, {s['fail']} FAIL, {s['unknown']} UNKNOWN")
    lines.append("")

    lines.append("## Fix List (priority order)")
    lines.append("")
    if not report["fix_list"]:
        lines.append("No FAIL findings — nothing to fix.")
    for item in report["fix_list"]:
        lines.append(f"### {item['priority']}. [{item['rule_id']}] {item['category']}")
        lines.append(f"- **Finding:** {item['finding']}")
        lines.append(f"- **Why it matters:** {item['why_it_matters']}")
        lines.append(f"- **Fix:** `{item['fix_command']}`")
        lines.append("")

    lines.append("## Full Findings")
    lines.append("")
    lines.append("| Rule ID | Title | Status | Evidence |")
    lines.append("|---|---|---|---|")
    for f in report["findings"]:
        evidence = f["evidence"].replace("\n", " ").replace("|", "\\|")
        if len(evidence) > 120:
            evidence = evidence[:117] + "..."
        lines.append(f"| {f['rule_id']} | {f['title']} | {f['status']} | {evidence} |")
    lines.append("")

    if report["unknowns"]:
        lines.append("## UNKNOWN (could not verify)")
        lines.append("")
        for f in report["unknowns"]:
            lines.append(f"- **{f['rule_id']}** ({f['title']}): {f['evidence']}")
        lines.append("")

    return "\n".join(lines)
