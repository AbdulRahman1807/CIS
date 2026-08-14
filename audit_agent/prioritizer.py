"""prioritizer.py — turns FAIL findings into a ranked, explained fix list
(WORKPLAN.md §2.3 contract). Deterministic templates only, no LLM (see
WORKPLAN.md §0) — this alone is sufficient to pass per handout Part 12.
Never marks PASS/FAIL itself; that verdict already happened in rules.py.
"""

from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

REMEDIATION_TEMPLATES = {
    "CIS-5.2.10": {
        "category": "SSH hardening",
        "finding_template": "Root login over SSH is permitted ({evidence}).",
        "why_it_matters": "A leaked or brute-forced root credential grants full remote access with no separate privilege step.",
        "fix_command": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
    },
    "CIS-5.2.11": {
        "category": "SSH hardening",
        "finding_template": "SSH password authentication is enabled ({evidence}), allowing brute-force login attempts.",
        "why_it_matters": "Password auth is vulnerable to brute-force and credential-stuffing attacks; key-based auth removes that attack surface entirely.",
        "fix_command": "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
    },
    "CIS-5.3.1": {
        "category": "Password policy",
        "finding_template": "Minimum password length policy is too weak or unset ({evidence}).",
        "why_it_matters": "Short passwords are far more susceptible to brute-force and dictionary attacks.",
        "fix_command": "sudo sed -i '/^PASS_MIN_LEN/d' /etc/login.defs && printf 'PASS_MIN_LEN\\t14\\n' | sudo tee -a /etc/login.defs",
    },
    "CIS-6.1.2": {
        "category": "File permissions",
        "finding_template": "/etc/passwd has incorrect ownership or permissions ({evidence}).",
        "why_it_matters": "Incorrect ownership on /etc/passwd can allow unauthorized users to modify account records.",
        "fix_command": "sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd",
    },
    "CIS-6.1.3": {
        "category": "File permissions",
        "finding_template": "/etc/shadow has incorrect ownership or permissions ({evidence}).",
        "why_it_matters": "/etc/shadow holds password hashes; loose permissions let unprivileged users read or crack them offline.",
        "fix_command": "sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow",
    },
    "CIS-6.1.10": {
        "category": "File permissions",
        "finding_template": "World-writable files found in sensitive system paths ({evidence}).",
        "why_it_matters": "A world-writable file under /etc or a system bin directory can be modified by any local user to escalate privileges or plant malicious content.",
        "fix_command": "sudo chmod o-w <file>   # apply to each file path listed in the evidence",
    },
    "CIS-3.5.1": {
        "category": "Network hardening",
        "finding_template": "No active default-deny firewall policy was found ({evidence}).",
        "why_it_matters": "Without a default-deny firewall policy, every listening service is directly reachable from the network.",
        "fix_command": "sudo iptables -P INPUT DROP && sudo iptables -A INPUT -i lo -j ACCEPT && sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    },
    "CIS-2.2.4": {
        "category": "Patch management",
        "finding_template": "Automatic security updates are not enabled ({evidence}).",
        "why_it_matters": "Unpatched systems remain exposed to publicly known vulnerabilities long after fixes are available.",
        "fix_command": "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
    },
    "CIS-5.4.1": {
        "category": "Account security",
        "finding_template": "One or more accounts have an empty password ({evidence}).",
        "why_it_matters": "An empty password lets anyone log in as that account with no credential at all.",
        "fix_command": "sudo passwd -l <account>   # lock each account listed in the evidence, or set a real password",
    },
    "CIS-5.2.9": {
        "category": "Privilege escalation",
        "finding_template": "A blanket NOPASSWD sudoers entry was found ({evidence}).",
        "why_it_matters": "A passwordless, unrestricted sudo rule lets anyone with access to that account become root with no additional authentication.",
        "fix_command": "sudo visudo   # remove the NOPASSWD:ALL line shown in the evidence",
    },
}


def prioritize(findings: list[dict]) -> list[dict]:
    """Filters to status == "FAIL" only. Sorts by
    (SEVERITY_ORDER[severity_hint], rule_id) — rule_id as tiebreak is what
    makes ordering deterministic across runs (WORKPLAN.md §5). Assigns
    priority = 1..N after sorting. Every item's evidence_ref == its
    rule_id, satisfying Requirement 5."""
    fails = [f for f in findings if f["status"] == "FAIL"]
    fails_sorted = sorted(
        fails, key=lambda f: (SEVERITY_ORDER.get(f["severity_hint"], 99), f["rule_id"])
    )

    fix_list = []
    for i, finding in enumerate(fails_sorted, start=1):
        template = REMEDIATION_TEMPLATES.get(finding["rule_id"])
        if template is None:
            # Every rule_id in rules.RULES must have a template here — if
            # this ever triggers, allowlist/rules/prioritizer have drifted
            # out of sync (WORKPLAN.md §3), not a normal runtime condition.
            continue
        fix_list.append(
            {
                "priority": i,
                "rule_id": finding["rule_id"],
                "category": template["category"],
                "finding": template["finding_template"].format(evidence=finding["evidence"]),
                "why_it_matters": template["why_it_matters"],
                "fix_command": template["fix_command"],
                "evidence_ref": finding["rule_id"],
            }
        )
    return fix_list
