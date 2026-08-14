import unittest
import os
import json
from audit_agent.rules import (
    evaluate,
    parse_ssh_root_login,
    parse_ssh_password_auth,
    parse_min_password_length,
    parse_stat_passwd,
    parse_stat_shadow,
    parse_world_writable,
    parse_firewall,
    parse_auto_updates,
    parse_empty_passwd,
    parse_sudoers
)

class TestRules(unittest.TestCase):
    
    def test_parse_ssh_root_login(self):
        # FAIL case
        status, evidence = parse_ssh_root_login("PermitRootLogin yes\n")
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence, "PermitRootLogin yes")
        
        # PASS case (disabled)
        status, evidence = parse_ssh_root_login("PermitRootLogin no\n")
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, "PermitRootLogin no")
        
        # PASS case (prohibit-password)
        status, evidence = parse_ssh_root_login("PermitRootLogin prohibit-password\n")
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, "PermitRootLogin prohibit-password")
        
        # Default PASS case (no direct match)
        status, evidence = parse_ssh_root_login("Port 22\n")
        self.assertEqual(status, "PASS")
        self.assertIn("directive not set", evidence)

    def test_parse_ssh_password_auth(self):
        # FAIL case
        status, evidence = parse_ssh_password_auth("PasswordAuthentication yes\n")
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence, "PasswordAuthentication yes")
        
        # PASS case
        status, evidence = parse_ssh_password_auth("PasswordAuthentication no\n")
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, "PasswordAuthentication no")
        
        # Default PASS case
        status, evidence = parse_ssh_password_auth("Port 22\n")
        self.assertEqual(status, "PASS")
        self.assertIn("directive not set", evidence)

    def test_parse_min_password_length(self):
        # PASS case
        status, evidence = parse_min_password_length("# Comments\nPASS_MIN_LEN 14\n")
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, "PASS_MIN_LEN 14")
        
        # FAIL case
        status, evidence = parse_min_password_length("PASS_MIN_LEN 5\n")
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence, "PASS_MIN_LEN 5")
        
        # Commented out case (should fail/not match)
        status, evidence = parse_min_password_length("# PASS_MIN_LEN 14\n")
        self.assertEqual(status, "FAIL")
        self.assertIn("not configured", evidence)

    def test_parse_stat_passwd(self):
        # PASS case
        status, evidence = parse_stat_passwd("root:root 644\n")
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, "root:root 644")
        
        # FAIL case (wrong owner)
        status, evidence = parse_stat_passwd("bin:root 644\n")
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence, "bin:root 644")
        
        # FAIL case (wrong mode)
        status, evidence = parse_stat_passwd("root:root 777\n")
        self.assertEqual(status, "FAIL")
        
        # Invalid format
        status, evidence = parse_stat_passwd("root:root\n")
        self.assertEqual(status, "FAIL")
        self.assertIn("Invalid stat output format", evidence)

    def test_parse_stat_shadow(self):
        # PASS cases
        status, evidence = parse_stat_shadow("root:shadow 640\n")
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, "root:shadow 640")
        
        status, evidence = parse_stat_shadow("root:root 600\n")
        self.assertEqual(status, "PASS")
        
        status, evidence = parse_stat_shadow("root:shadow 000\n")
        self.assertEqual(status, "PASS")
        
        # FAIL case (wrong owner)
        status, evidence = parse_stat_shadow("bin:shadow 640\n")
        self.assertEqual(status, "FAIL")
        
        # FAIL case (wrong mode)
        status, evidence = parse_stat_shadow("root:shadow 644\n")
        self.assertEqual(status, "FAIL")

    def test_parse_world_writable(self):
        # PASS case
        status, evidence = parse_world_writable("")
        self.assertEqual(status, "PASS")
        self.assertIn("No world-writable files found", evidence)
        
        # FAIL case
        status, evidence = parse_world_writable("/etc/writable1\n/etc/writable2\n")
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence, "/etc/writable1\n/etc/writable2")

    def test_parse_firewall(self):
        # PASS case (policy DROP)
        status, evidence = parse_firewall("Chain INPUT (policy DROP)\ntarget prot opt source destination\n")
        self.assertEqual(status, "PASS")
        self.assertIn("INPUT policy: DROP", evidence)
        
        # PASS case (policy ACCEPT with DROP/REJECT rule)
        status, evidence = parse_firewall("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\nDROP all -- 0.0.0.0/0 0.0.0.0/0\n")
        self.assertEqual(status, "PASS")
        self.assertIn("filtering rules found", evidence)
        
        # FAIL case (policy ACCEPT with no rules)
        status, evidence = parse_firewall("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n")
        self.assertEqual(status, "FAIL")
        self.assertIn("Firewall inactive", evidence)

    def test_parse_auto_updates(self):
        # PASS case
        status, evidence = parse_auto_updates('APT::Periodic::Unattended-Upgrade "1";\n')
        self.assertEqual(status, "PASS")
        self.assertEqual(evidence, 'APT::Periodic::Unattended-Upgrade "1";')
        
        # FAIL case (disabled)
        status, evidence = parse_auto_updates('APT::Periodic::Unattended-Upgrade "0";\n')
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence, 'APT::Periodic::Unattended-Upgrade "0";')
        
        # FAIL case (not set)
        status, evidence = parse_auto_updates('')
        self.assertEqual(status, "FAIL")
        self.assertIn("not found or disabled", evidence)

    def test_parse_empty_passwd(self):
        # PASS case
        status, evidence = parse_empty_passwd("")
        self.assertEqual(status, "PASS")
        
        # FAIL case
        status, evidence = parse_empty_passwd("cis_test_emptypass\n")
        self.assertEqual(status, "FAIL")
        self.assertIn("cis_test_emptypass", evidence)

    def test_parse_sudoers(self):
        # PASS case
        status, evidence = parse_sudoers("")
        self.assertEqual(status, "PASS")
        
        # FAIL case
        status, evidence = parse_sudoers("/etc/sudoers:ALL ALL=(ALL) NOPASSWD:ALL\n")
        self.assertEqual(status, "FAIL")
        self.assertIn("NOPASSWD:ALL", evidence)

    def test_evaluate_success_and_failures(self):
        # Test full integration evaluating mock captures
        captures = [
            {
                "command_id": "cmd_sshd_config",
                "os_family": "linux",
                "argv": ["sshd", "-T"],
                "exit_code": 0,
                "stdout": "permitrootlogin yes\npasswordauthentication yes\n",
                "stderr": "",
                "status": "ok"
            },
            {
                "command_id": "cmd_login_defs",
                "os_family": "linux",
                "argv": ["cat", "/etc/login.defs"],
                "exit_code": 0,
                "stdout": "PASS_MIN_LEN 5\n",
                "stderr": "",
                "status": "ok"
            },
            {
                "command_id": "cmd_stat_passwd",
                "os_family": "linux",
                "argv": ["stat", "-c", "%U:%G %a", "/etc/passwd"],
                "exit_code": 0,
                "stdout": "root:root 644\n",
                "stderr": "",
                "status": "ok"
            },
            {
                "command_id": "cmd_stat_shadow",
                "os_family": "linux",
                "argv": ["stat", "-c", "%U:%G %a", "/etc/shadow"],
                "exit_code": 0,
                "stdout": "root:shadow 640\n",
                "stderr": "",
                "status": "ok"
            },
            {
                "command_id": "cmd_world_writable",
                "os_family": "linux",
                "argv": ["find", "/etc"],
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "status": "ok"
            },
            {
                "command_id": "cmd_firewall",
                "os_family": "linux",
                "argv": ["iptables"],
                "exit_code": 1,
                "stdout": "",
                "stderr": "executable file not found",
                "status": "unavailable",
                "reason": "binary not found in container"
            },
            {
                "command_id": "cmd_auto_updates",
                "os_family": "linux",
                "argv": ["cat", "/etc/apt/apt.conf.d/20auto-upgrades"],
                "exit_code": 1,
                "stdout": "",
                "stderr": "",
                "status": "ok"
            },
            {
                "command_id": "cmd_empty_passwd",
                "os_family": "linux",
                "argv": ["awk"],
                "exit_code": 1,
                "stdout": "",
                "stderr": "permission denied",
                "status": "unavailable",
                "reason": "permission denied"
            },
            {
                "command_id": "cmd_sudoers",
                "os_family": "linux",
                "argv": ["grep"],
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "status": "ok"
            }
        ]
        
        findings = evaluate(captures)
        
        # Verify 10 rules returned
        self.assertEqual(len(findings), 10)
        
        # Verify order and details
        # CIS-5.2.10 (sshd root login) -> FAIL
        self.assertEqual(findings[0]["rule_id"], "CIS-5.2.10")
        self.assertEqual(findings[0]["status"], "FAIL")
        
        # CIS-5.2.11 (sshd password auth) -> FAIL (reuses cmd_sshd_config)
        self.assertEqual(findings[1]["rule_id"], "CIS-5.2.11")
        self.assertEqual(findings[1]["status"], "FAIL")
        
        # CIS-5.3.1 (login_defs) -> FAIL (len 5 < 14)
        self.assertEqual(findings[2]["rule_id"], "CIS-5.3.1")
        self.assertEqual(findings[2]["status"], "FAIL")
        
        # CIS-6.1.2 (passwd perms) -> PASS
        self.assertEqual(findings[3]["rule_id"], "CIS-6.1.2")
        self.assertEqual(findings[3]["status"], "PASS")
        
        # CIS-6.1.3 (shadow perms) -> PASS
        self.assertEqual(findings[4]["rule_id"], "CIS-6.1.3")
        self.assertEqual(findings[4]["status"], "PASS")
        
        # CIS-6.1.10 (world writable) -> PASS (empty output)
        self.assertEqual(findings[5]["rule_id"], "CIS-6.1.10")
        self.assertEqual(findings[5]["status"], "PASS")
        
        # CIS-3.5.1 (firewall) -> UNKNOWN (status != ok)
        self.assertEqual(findings[6]["rule_id"], "CIS-3.5.1")
        self.assertEqual(findings[6]["status"], "UNKNOWN")
        self.assertEqual(findings[6]["evidence"], "binary not found in container")
        
        # CIS-2.2.4 (auto updates) -> FAIL
        self.assertEqual(findings[7]["rule_id"], "CIS-2.2.4")
        self.assertEqual(findings[7]["status"], "FAIL")
        
        # CIS-5.4.1 (empty passwd) -> UNKNOWN
        self.assertEqual(findings[8]["rule_id"], "CIS-5.4.1")
        self.assertEqual(findings[8]["status"], "UNKNOWN")
        self.assertEqual(findings[8]["evidence"], "permission denied")
        
        # CIS-5.2.9 (sudoers NOPASSWD) -> PASS
        self.assertEqual(findings[9]["rule_id"], "CIS-5.2.9")
        self.assertEqual(findings[9]["status"], "PASS")

    def test_evaluate_from_fixture_file(self):
        fixture_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit_agent", "fixtures", "sample_captures.json")
        with open(fixture_path, "r") as f:
            captures = json.load(f)
        findings = evaluate(captures)
        self.assertEqual(len(findings), 10)
        
        # Verify specific rules parsed from the resolved captures:
        # CIS-5.2.10 (sshd root login) -> FAIL
        self.assertEqual(findings[0]["rule_id"], "CIS-5.2.10")
        self.assertEqual(findings[0]["status"], "FAIL")
        
        # CIS-5.2.11 (sshd password auth) -> FAIL
        self.assertEqual(findings[1]["rule_id"], "CIS-5.2.11")
        self.assertEqual(findings[1]["status"], "FAIL")
        
        # CIS-5.3.1 (login_defs) -> FAIL
        self.assertEqual(findings[2]["rule_id"], "CIS-5.3.1")
        self.assertEqual(findings[2]["status"], "FAIL")
        
        # CIS-6.1.2 (passwd perms) -> PASS
        self.assertEqual(findings[3]["rule_id"], "CIS-6.1.2")
        self.assertEqual(findings[3]["status"], "PASS")
        
        # CIS-6.1.3 (shadow perms) -> PASS
        self.assertEqual(findings[4]["rule_id"], "CIS-6.1.3")
        self.assertEqual(findings[4]["status"], "PASS")
        
        # CIS-6.1.10 (world-writable) -> FAIL
        self.assertEqual(findings[5]["rule_id"], "CIS-6.1.10")
        self.assertEqual(findings[5]["status"], "FAIL")
        
        # CIS-3.5.1 (firewall) -> FAIL
        self.assertEqual(findings[6]["rule_id"], "CIS-3.5.1")
        self.assertEqual(findings[6]["status"], "FAIL")
        
        # CIS-2.2.4 (auto updates) -> FAIL
        self.assertEqual(findings[7]["rule_id"], "CIS-2.2.4")
        self.assertEqual(findings[7]["status"], "FAIL")
        
        # CIS-5.4.1 (empty password accounts) -> FAIL
        self.assertEqual(findings[8]["rule_id"], "CIS-5.4.1")
        self.assertEqual(findings[8]["status"], "FAIL")
        
        # CIS-5.2.9 (blanket NOPASSWD:ALL) -> FAIL
        self.assertEqual(findings[9]["rule_id"], "CIS-5.2.9")
        self.assertEqual(findings[9]["status"], "FAIL")

if __name__ == "__main__":
    unittest.main()
