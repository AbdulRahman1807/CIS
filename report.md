# CIS Audit Report — cis-misconfigured

Generated: 2026-08-14T05:48:12.321976+00:00 via docker

**Summary:** 2 PASS, 8 FAIL, 0 UNKNOWN

## Fix List (priority order)

### 1. [CIS-5.4.1] Account security
- **Finding:** One or more accounts have an empty password (cis_test_emptypass).
- **Why it matters:** An empty password lets anyone log in as that account with no credential at all.
- **Fix:** `sudo passwd -l <account>   # lock each account listed in the evidence, or set a real password`

### 2. [CIS-3.5.1] Network hardening
- **Finding:** No active default-deny firewall policy was found (Chain INPUT (policy ACCEPT)
target     prot opt source               destination).
- **Why it matters:** Without a default-deny firewall policy, every listening service is directly reachable from the network.
- **Fix:** `sudo iptables -P INPUT DROP && sudo iptables -A INPUT -i lo -j ACCEPT && sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT`

### 3. [CIS-5.2.10] SSH hardening
- **Finding:** Root login over SSH is permitted (PermitRootLogin yes).
- **Why it matters:** A leaked or brute-forced root credential grants full remote access with no separate privilege step.
- **Fix:** `sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd`

### 4. [CIS-5.2.11] SSH hardening
- **Finding:** SSH password authentication is enabled (PasswordAuthentication yes), allowing brute-force login attempts.
- **Why it matters:** Password auth is vulnerable to brute-force and credential-stuffing attacks; key-based auth removes that attack surface entirely.
- **Fix:** `sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd`

### 5. [CIS-5.2.9] Privilege escalation
- **Finding:** A blanket NOPASSWD sudoers entry was found (/etc/sudoers.d/90-cis-test-nopasswd:ALL ALL=(ALL) NOPASSWD:ALL).
- **Why it matters:** A passwordless, unrestricted sudo rule lets anyone with access to that account become root with no additional authentication.
- **Fix:** `sudo visudo   # remove the NOPASSWD:ALL line shown in the evidence`

### 6. [CIS-2.2.4] Patch management
- **Finding:** Automatic security updates are not enabled (20auto-upgrades config not found or not enabled).
- **Why it matters:** Unpatched systems remain exposed to publicly known vulnerabilities long after fixes are available.
- **Fix:** `sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`

### 7. [CIS-5.3.1] Password policy
- **Finding:** Minimum password length policy is too weak or unset (PASS_MIN_LEN	5).
- **Why it matters:** Short passwords are far more susceptible to brute-force and dictionary attacks.
- **Fix:** `sudo sed -i '/^PASS_MIN_LEN/d' /etc/login.defs && printf 'PASS_MIN_LEN\t14\n' | sudo tee -a /etc/login.defs`

### 8. [CIS-6.1.10] File permissions
- **Finding:** World-writable files found in sensitive system paths (/etc/cis_test_world_writable).
- **Why it matters:** A world-writable file under /etc or a system bin directory can be modified by any local user to escalate privileges or plant malicious content.
- **Fix:** `sudo chmod o-w <file>   # apply to each file path listed in the evidence`

## Full Findings

| Rule ID | Title | Status | Evidence |
|---|---|---|---|
| CIS-5.2.10 | SSH root login disabled | FAIL | PermitRootLogin yes |
| CIS-5.2.11 | SSH password auth disabled | FAIL | PasswordAuthentication yes |
| CIS-5.3.1 | Minimum password length ≥14 | FAIL | PASS_MIN_LEN	5 |
| CIS-6.1.2 | /etc/passwd ownership/perms | PASS | root:root 644 |
| CIS-6.1.3 | /etc/shadow ownership/perms | PASS | root:shadow 640 |
| CIS-6.1.10 | No world-writable files in /etc, /usr/bin, /usr/sbin | FAIL | /etc/cis_test_world_writable |
| CIS-3.5.1 | Firewall active | FAIL | Chain INPUT (policy ACCEPT) target     prot opt source               destination |
| CIS-2.2.4 | Automatic security updates enabled | FAIL | 20auto-upgrades config not found or not enabled |
| CIS-5.4.1 | No accounts with empty passwords | FAIL | cis_test_emptypass |
| CIS-5.2.9 | No blanket NOPASSWD wildcard in sudoers | FAIL | /etc/sudoers.d/90-cis-test-nopasswd:ALL ALL=(ALL) NOPASSWD:ALL |
