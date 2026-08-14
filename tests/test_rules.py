# Person B owns this file.

import json
from pathlib import Path

from audit_agent import rules

FIXTURES = Path(__file__).parent.parent / "audit_agent" / "fixtures"


def test_evaluate_against_sample_captures():
    # Once audit_agent/fixtures/sample_captures.json exists (Person A),
    # load it here and assert on the resulting findings.
    pass
