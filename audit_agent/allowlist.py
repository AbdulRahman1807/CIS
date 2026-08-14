"""allowlist.py — the ONE place read-only commands are defined.

Every argv here is a literal list. Nothing constructs a command by string
interpolation, and no rule engine, LLM, or config file may request a command
that isn't in this list (WORKPLAN.md §0 / handout Part 6.5).

command_id values are shared with rules.py (see WORKPLAN.md §3) — the two
files must be kept in sync manually, there is no single source of truth
beyond this comment and the table in WORKPLAN.md.
"""

COMMANDS = {
    "linux": [
        {
            "command_id": "cmd_sshd_config",
            "argv": ["grep", "-iE", "^(PermitRootLogin|PasswordAuthentication)", "/etc/ssh/sshd_config"],
        },
        {"command_id": "cmd_login_defs", "argv": ["cat", "/etc/login.defs"]},
        {"command_id": "cmd_stat_passwd", "argv": ["stat", "-c", "%U:%G %a", "/etc/passwd"]},
        {"command_id": "cmd_stat_shadow", "argv": ["stat", "-c", "%U:%G %a", "/etc/shadow"]},
        {
            "command_id": "cmd_world_writable",
            "argv": ["find", "/etc", "/usr/bin", "/usr/sbin", "-xdev", "-type", "f", "-perm", "-0002"],
        },
        {"command_id": "cmd_firewall", "argv": ["iptables", "-L", "INPUT", "-n"]},
        {"command_id": "cmd_auto_updates", "argv": ["cat", "/etc/apt/apt.conf.d/20auto-upgrades"]},
        {"command_id": "cmd_empty_passwd", "argv": ["awk", "-F:", '($2==""){print $1}', "/etc/shadow"]},
        {"command_id": "cmd_sudoers", "argv": ["grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d"]},
    ],
    # "darwin": [],  # NOT built this hackathon — see WORKPLAN.md §0.
}
