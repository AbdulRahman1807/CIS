"""cli.py — entrypoint: python -m audit_agent.cli --target <container_name>

Wires connector.open_session -> collector.run_all -> rules.evaluate ->
prioritizer.prioritize -> report.build_report -> writes report.json +
report.md. If open_session() raises, exits 1 with the error on stderr and
nothing else runs (Requirement 9). All other command-level failures are
already caught inside collector and surfaced as UNKNOWN — nothing here
needs to catch them again.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import collector, connector, prioritizer, report as report_mod, rules


def main() -> None:
    parser = argparse.ArgumentParser(prog="audit-agent")
    parser.add_argument("--target", required=True, help="docker container name")
    parser.add_argument("--report-json", default="report.json")
    parser.add_argument("--report-md", default="report.md")
    args = parser.parse_args()

    try:
        session = connector.open_session(args.target)
    except connector.ConnectorError as exc:
        print(f"error: could not open a session against {args.target!r}: {exc}", file=sys.stderr)
        sys.exit(1)

    captures = collector.run_all(session, debug_dump_path=None)
    findings = rules.evaluate(captures)
    fix_list = prioritizer.prioritize(findings)
    meta = {
        "target": args.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "transport": "docker",
    }
    report = report_mod.build_report(findings, fix_list, meta)

    with open(args.report_json, "w") as f:
        json.dump(report, f, indent=2)
    with open(args.report_md, "w") as f:
        f.write(report_mod.render_markdown(report))

    # Best-effort copy for the React UI's static fetch (ui/public/report.json)
    # — never fatal, the CLI's job is done once report.json/.md are written.
    ui_public = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "public")
    if os.path.isdir(ui_public):
        try:
            with open(os.path.join(ui_public, "report.json"), "w") as f:
                json.dump(report, f, indent=2)
        except OSError:
            pass

    print(f"wrote {args.report_json} and {args.report_md}")
    print(f"{report['summary']['pass']} PASS, {report['summary']['fail']} FAIL, {report['summary']['unknown']} UNKNOWN")


if __name__ == "__main__":
    main()
