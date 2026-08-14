# CIS Audit Report — cis-clean

Generated: 2026-08-14T07:13:58.019301+00:00 via docker

**Summary:** 10 PASS, 0 FAIL, 0 UNKNOWN

## Fix List (priority order)

No FAIL findings — nothing to fix.
## Full Findings

| Rule ID | Title | Status | Evidence |
|---|---|---|---|
| CIS-5.2.10 | SSH root login disabled | PASS | PermitRootLogin not set to yes |
| CIS-5.2.11 | SSH password auth disabled | PASS | PasswordAuthentication not set to yes |
| CIS-5.3.1 | Minimum password length ≥14 | PASS | PASS_MIN_LEN	14 |
| CIS-6.1.2 | /etc/passwd ownership/perms | PASS | root:root 644 |
| CIS-6.1.3 | /etc/shadow ownership/perms | PASS | root:shadow 640 |
| CIS-6.1.10 | No world-writable files in /etc, /usr/bin, /usr/sbin | PASS | no world-writable files found |
| CIS-3.5.1 | Firewall active | PASS | INPUT policy is DROP |
| CIS-2.2.4 | Automatic security updates enabled | PASS | APT::Periodic::Unattended-Upgrade "1"; |
| CIS-5.4.1 | No accounts with empty passwords | PASS | no accounts with empty passwords |
| CIS-5.2.9 | No blanket NOPASSWD wildcard in sudoers | PASS | no NOPASSWD entries found |
