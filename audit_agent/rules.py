"""rules.py — evaluates the 10 locked CIS-style rules (WORKPLAN.md §3)
against collector.run_all()'s captures (§2.1 contract) and returns Finding
dicts (§2.2 contract). Parsers are boring regex/exact-match, per handout §6.1
— no cleverness, no guessing.
"""

from __future__ import annotations

import re


def _parse_ssh_root_login(stdout: str):
    for line in stdout.splitlines():
        if re.match(r"(?i)^permitrootlogin\s+yes\b", line.strip()):
            return "FAIL", line.strip()
    return "PASS", "PermitRootLogin not set to yes"


def _parse_ssh_password_auth(stdout: str):
    for line in stdout.splitlines():
        if re.match(r"(?i)^passwordauthentication\s+yes\b", line.strip()):
            return "FAIL", line.strip()
    return "PASS", "PasswordAuthentication not set to yes"


def _parse_pass_min_len(stdout: str):
    for line in stdout.splitlines():
        m = re.match(r"^PASS_MIN_LEN\s+(\d+)", line)
        if m:
            n = int(m.group(1))
            evidence = line.strip()
            return ("PASS" if n >= 14 else "FAIL"), evidence
    return "FAIL", "PASS_MIN_LEN not set in /etc/login.defs"


def _parse_stat_passwd(stdout: str):
    line = stdout.strip()
    if line == "root:root 644":
        return "PASS", line
    return "FAIL", line or "no output"


def _parse_stat_shadow(stdout: str):
    line = stdout.strip()
    m = re.match(r"^([^:]+):([^ ]+) (\d+)$", line)
    if m:
        owner, _group, mode = m.group(1), m.group(2), m.group(3)
        if owner == "root" and mode in ("640", "600", "000"):
            return "PASS", line
    return "FAIL", line or "no output"


def _parse_world_writable(stdout: str):
    if stdout.strip() == "":
        return "PASS", "no world-writable files found"
    return "FAIL", stdout.strip()


def _parse_firewall(stdout: str):
    m = re.search(r"Chain INPUT \(policy (\w+)\)", stdout)
    policy = m.group(1) if m else None
    has_drop_reject_rule = bool(re.search(r"\b(DROP|REJECT)\b", stdout[m.end():] if m else stdout))
    if policy and policy != "ACCEPT":
        return "PASS", f"INPUT policy is {policy}"
    if has_drop_reject_rule:
        return "PASS", "INPUT policy is ACCEPT but a DROP/REJECT rule is present"
    return "FAIL", (stdout.strip() or "no firewall rules found")


def _parse_auto_updates(stdout: str):
    if re.search(r'Unattended-Upgrade\s*"1"', stdout):
        first_line = next((l for l in stdout.splitlines() if "Unattended-Upgrade" in l), stdout.strip())
        return "PASS", first_line.strip()
    return "FAIL", (stdout.strip() or "20auto-upgrades config not found or not enabled")


def _parse_empty_passwd(stdout: str):
    if stdout.strip() == "":
        return "PASS", "no accounts with empty passwords"
    return "FAIL", stdout.strip()


def _parse_sudoers(stdout: str):
    if stdout.strip() == "":
        return "PASS", "no NOPASSWD entries found"
    return "FAIL", stdout.strip()


# Parsing functions for each rule

def parse_ssh_root_login(stdout):
    match = re.search(r'(?i)^\s*permitrootlogin\s+yes\b', stdout, re.MULTILINE)
    if match:
        return "FAIL", match.group(0).strip()
    pass_match = re.search(r'(?i)^\s*permitrootlogin\s+\S+', stdout, re.MULTILINE)
    if pass_match:
        return "PASS", pass_match.group(0).strip()
    return "PASS", "permitrootlogin directive not set (defaults to disabled/prohibit-password)"

def parse_ssh_password_auth(stdout):
    match = re.search(r'(?i)^\s*passwordauthentication\s+yes\b', stdout, re.MULTILINE)
    if match:
        return "FAIL", match.group(0).strip()
    pass_match = re.search(r'(?i)^\s*passwordauthentication\s+\S+', stdout, re.MULTILINE)
    if pass_match:
        return "PASS", pass_match.group(0).strip()
    return "PASS", "passwordauthentication directive not set (defaults to no)"

def parse_min_password_length(stdout):
    # Match uncommented PASS_MIN_LEN lines
    matches = re.findall(r'^\s*PASS_MIN_LEN\s+(\d+)\b', stdout, re.MULTILINE)
    if not matches:
        return "FAIL", "PASS_MIN_LEN not configured in /etc/login.defs"
    val = int(matches[-1])  # Use the last defined value
    evidence = f"PASS_MIN_LEN {val}"
    if val >= 14:
        return "PASS", evidence
    else:
        return "FAIL", evidence

def parse_stat_passwd(stdout):
    stdout_clean = stdout.strip()
    if not stdout_clean:
        return "FAIL", "No output from stat"
    parts = stdout_clean.split()
    if len(parts) < 2:
        return "FAIL", f"Invalid stat output format: {stdout_clean}"
    owner_group, mode = parts[0], parts[1]
    if owner_group == "root:root" and mode == "644":
        return "PASS", stdout_clean
    else:
        return "FAIL", stdout_clean

def parse_stat_shadow(stdout):
    stdout_clean = stdout.strip()
    if not stdout_clean:
        return "FAIL", "No output from stat"
    parts = stdout_clean.split()
    if len(parts) < 2:
        return "FAIL", f"Invalid stat output format: {stdout_clean}"
    owner_group, mode = parts[0], parts[1]
    owner = owner_group.split(':')[0] if ':' in owner_group else owner_group
    if owner == "root" and mode in ("640", "600", "000"):
        return "PASS", stdout_clean
    else:
        return "FAIL", stdout_clean

def parse_world_writable(stdout):
    stdout_clean = stdout.strip()
    if not stdout_clean:
        return "PASS", "No world-writable files found"
    lines = stdout_clean.splitlines()
    evidence = "\n".join(lines[:5])
    if len(lines) > 5:
        evidence += f"\n... and {len(lines) - 5} more files"
    return "FAIL", evidence

def parse_firewall(stdout):
    # Find Chain INPUT policy
    policy_match = re.search(r'Chain INPUT \(policy ([A-Z]+)\)', stdout)
    if not policy_match:
        return "FAIL", "No Chain INPUT policy found in iptables output"
    policy = policy_match.group(1)
    if policy != "ACCEPT":
        return "PASS", f"Firewall active (INPUT policy: {policy})"
    
    # If policy is ACCEPT, check for filtering rules
    lines = stdout.strip().splitlines()
    rules_found = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) > 0 and parts[0] in ("DROP", "REJECT"):
            rules_found.append(line.strip())
            
    if rules_found:
        return "PASS", f"Firewall active (policy ACCEPT but filtering rules found: {rules_found[0]})"
    else:
        return "FAIL", "Firewall inactive (INPUT policy is ACCEPT and no DROP/REJECT rules exist)"

def parse_auto_updates(stdout):
    match = re.search(r'(?i)^\s*(?![/#]).*unattended-upgrade\s+["\']?1["\']?.*', stdout, re.MULTILINE)
    if match:
        return "PASS", match.group(0).strip()
    
    any_config = re.search(r'(?i)^\s*(?![/#]).*unattended-upgrade\s+\S+.*', stdout, re.MULTILINE)
    if any_config:
        return "FAIL", any_config.group(0).strip()
    return "FAIL", "Unattended-Upgrade setting not found or disabled"

def parse_empty_passwd(stdout):
    stdout_clean = stdout.strip()
    if not stdout_clean:
        return "PASS", "No accounts with empty passwords found"
    lines = stdout_clean.splitlines()
    evidence = f"Accounts with empty passwords: {', '.join(lines)}"
    return "FAIL", evidence

def parse_sudoers(stdout):
    stdout_clean = stdout.strip()
    if not stdout_clean:
        return "PASS", "No NOPASSWD:ALL wildcards found in sudoers"
    lines = stdout_clean.splitlines()
    evidence = "\n".join(lines[:3])
    if len(lines) > 3:
        evidence += f"\n... and {len(lines) - 3} more lines"
    return "FAIL", evidence


# Canonical list of 10 rules
RULES = [
    {
        "rule_id": "CIS-5.2.10",
        "title": "SSH root login disabled",
        "command_id": "cmd_sshd_config",
        "severity_hint": "high",
        "parse": _parse_ssh_root_login,
    },
    {
        "rule_id": "CIS-5.2.11",
        "title": "SSH password auth disabled",
        "command_id": "cmd_sshd_config",
        "severity_hint": "high",
        "parse": _parse_ssh_password_auth,
    },
    {
        "rule_id": "CIS-5.3.1",
        "title": "Minimum password length ≥14",
        "command_id": "cmd_login_defs",
        "severity_hint": "medium",
        "parse": _parse_pass_min_len,
    },
    {
        "rule_id": "CIS-6.1.2",
        "title": "/etc/passwd ownership/perms",
        "command_id": "cmd_stat_passwd",
        "severity_hint": "medium",
        "parse": _parse_stat_passwd,
    },
    {
        "rule_id": "CIS-6.1.3",
        "title": "/etc/shadow ownership/perms",
        "command_id": "cmd_stat_shadow",
        "severity_hint": "high",
        "parse": _parse_stat_shadow,
    },
    {
        "rule_id": "CIS-6.1.10",
        "title": "No world-writable files in /etc, /usr/bin, /usr/sbin",
        "command_id": "cmd_world_writable",
        "severity_hint": "medium",
        "parse": _parse_world_writable,
    },
    {
        "rule_id": "CIS-3.5.1",
        "title": "Firewall active",
        "command_id": "cmd_firewall",
        "severity_hint": "high",
        "parse": _parse_firewall,
    },
    {
        "rule_id": "CIS-2.2.4",
        "title": "Automatic security updates enabled",
        "command_id": "cmd_auto_updates",
        "severity_hint": "medium",
        "parse": _parse_auto_updates,
    },
    {
        "rule_id": "CIS-5.4.1",
        "title": "No accounts with empty passwords",
        "command_id": "cmd_empty_passwd",
        "severity_hint": "critical",
        "parse": _parse_empty_passwd,
    },
    {
        "rule_id": "CIS-5.2.9",
        "title": "No blanket NOPASSWD wildcard in sudoers",
        "command_id": "cmd_sudoers",
        "severity_hint": "high",
        "parse": _parse_sudoers,
    },
]


def evaluate(captures: list[dict]) -> list[dict]:
    """captures = collector.run_all() output (WORKPLAN.md §2.1 contract).
    Returns one Finding dict (§2.2 contract) per rule in RULES, in RULES
    order — that fixed order is what keeps output deterministic (§5/§6
    no-drift). Never invents a PASS/FAIL when the underlying capture wasn't
    captured cleanly — status != "ok" always resolves to UNKNOWN with the
    capture's own logged reason as evidence."""
    by_command_id = {c["command_id"]: c for c in captures}
    findings = []
    for rule in RULES:
        capture = by_command_id.get(rule["command_id"])
        if capture is None:
            findings.append(
                {
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "command": "(not captured)",
                    "status": "UNKNOWN",
                    "evidence": f"no capture found for command_id {rule['command_id']!r}",
                    "severity_hint": rule["severity_hint"],
                }
            )
            continue

        command_str = " ".join(capture["argv"])

        if capture["status"] != "ok":
            findings.append(
                {
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "command": command_str,
                    "status": "UNKNOWN",
                    "evidence": capture.get("reason") or capture.get("stderr") or "command unavailable",
                    "severity_hint": rule["severity_hint"],
                }
            )
            continue

        status, evidence = rule["parse"](capture["stdout"])
        findings.append(
            {
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "command": command_str,
                "status": status,
                "evidence": evidence,
                "severity_hint": rule["severity_hint"],
            }
        )
    return findings
