import re

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
        "parse": parse_ssh_root_login
    },
    {
        "rule_id": "CIS-5.2.11",
        "title": "SSH password auth disabled",
        "command_id": "cmd_sshd_config",
        "severity_hint": "high",
        "parse": parse_ssh_password_auth
    },
    {
        "rule_id": "CIS-5.3.1",
        "title": "Minimum password length \u226514",
        "command_id": "cmd_login_defs",
        "severity_hint": "medium",
        "parse": parse_min_password_length
    },
    {
        "rule_id": "CIS-6.1.2",
        "title": "/etc/passwd ownership/perms",
        "command_id": "cmd_stat_passwd",
        "severity_hint": "medium",
        "parse": parse_stat_passwd
    },
    {
        "rule_id": "CIS-6.1.3",
        "title": "/etc/shadow ownership/perms",
        "command_id": "cmd_stat_shadow",
        "severity_hint": "high",
        "parse": parse_stat_shadow
    },
    {
        "rule_id": "CIS-6.1.10",
        "title": "No world-writable files in /etc, /usr/bin, /usr/sbin",
        "command_id": "cmd_world_writable",
        "severity_hint": "medium",
        "parse": parse_world_writable
    },
    {
        "rule_id": "CIS-3.5.1",
        "title": "Firewall active",
        "command_id": "cmd_firewall",
        "severity_hint": "high",
        "parse": parse_firewall
    },
    {
        "rule_id": "CIS-2.2.4",
        "title": "Automatic security updates enabled",
        "command_id": "cmd_auto_updates",
        "severity_hint": "medium",
        "parse": parse_auto_updates
    },
    {
        "rule_id": "CIS-5.4.1",
        "title": "No accounts with empty passwords",
        "command_id": "cmd_empty_passwd",
        "severity_hint": "critical",
        "parse": parse_empty_passwd
    },
    {
        "rule_id": "CIS-5.2.9",
        "title": "No blanket NOPASSWD:ALL in sudoers",
        "command_id": "cmd_sudoers",
        "severity_hint": "high",
        "parse": parse_sudoers
    }
]


def evaluate(captures: list[dict]) -> list[dict]:
    """
    Evaluates the list of command captures against the 10 defined rules.
    Returns a list of Finding dicts in the order of RULES.
    If capture is unavailable, status is UNKNOWN.
    """
    findings = []
    
    # Index captures by command_id for efficient lookup
    capture_map = {c["command_id"]: c for c in captures}
    
    for rule in RULES:
        cmd_id = rule["command_id"]
        capture = capture_map.get(cmd_id)
        
        # Determine finding fields
        finding = {
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "command": " ".join(capture["argv"]) if capture else "unknown command",
            "severity_hint": rule["severity_hint"]
        }
        
        if not capture:
            finding["status"] = "UNKNOWN"
            finding["evidence"] = "Command capture missing"
        elif capture.get("status") != "ok":
            finding["status"] = "UNKNOWN"
            reason = capture.get("reason")
            stderr = capture.get("stderr")
            finding["evidence"] = reason or stderr or f"Capture status is {capture.get('status')}"
        else:
            try:
                status, evidence = rule["parse"](capture.get("stdout", ""))
                finding["status"] = status
                finding["evidence"] = evidence
            except Exception as e:
                finding["status"] = "UNKNOWN"
                finding["evidence"] = f"Parser error: {str(e)}"
                
        findings.append(finding)
        
    return findings
