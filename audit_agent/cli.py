# Person C owns this file. See WORKPLAN.md §4 for the exact contract.
#
# Entrypoint: python -m audit_agent.cli --target <container_name>
# Wires: connector.open_session -> collector.run_all -> rules.evaluate ->
# prioritizer.prioritize -> report.build_report -> writes report.json +
# report.md. If open_session() raises, exit(1) with the error on stderr —
# nothing else runs. All other command-level failures are caught inside
# collector and surfaced as UNKNOWN, never crash the run.
#
# report.json also gets copied/written to ui/public/report.json so the
# React dev server can fetch it as a static asset — see ui/README (once
# Person B writes it) for the exact path.

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="audit-agent")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    raise NotImplementedError


if __name__ == "__main__":
    main()
