# Person C owns this file.

import json
from pathlib import Path

from audit_agent import prioritizer

FIXTURES = Path(__file__).parent.parent / "audit_agent" / "fixtures"


def test_prioritize_against_sample_findings():
    findings = json.loads((FIXTURES / "sample_findings.json").read_text())
    result = prioritizer.prioritize(findings)
    assert isinstance(result, list)
