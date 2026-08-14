# CIS Audit Agent — 3-Person / 3-Hour Work Split

Read this whole document before writing code. Every filename, function signature,
and JSON shape below is **locked** — do not invent alternatives mid-build. If
something needs to change, all three people agree in chat first, then this file
gets updated. Drift between what Person A produces and what Person B expects to
consume is the #1 way this project fails at hour 2.

Timekeeper: nominate one person now. They call out the Part 8 checkpoints below
out loud.

---

## 0. Locked decisions (do not re-litigate mid-build)

- **Language:** Python 3. Stdlib + `subprocess` only for the core path. No
  `paramiko`, no `docker` SDK — both add setup risk you don't have time for.
- **Transport:** `docker exec` against a local container. This is the primary
  and *only* transport for the 3-hour build. SSH is explicitly out of scope —
  it's the stretch item in Part 7.2, and only worth touching after everything
  below is committed and working.
- **LLM:** **OFF by default.** Ship a fully deterministic rule engine +
  template-based prioritizer. Per the handout's own FAQ (Part 12) and marking
  note (Part 11): a static, evidenced, drift-free engine beats an LLM engine
  that occasionally hallucinates a verdict. If time remains after 2:15 and the
  organisers have confirmed an LLM/API key is permitted, Person C adds it
  behind an `--llm` flag that never changes PASS/FAIL verdicts — see §5.
- **Repo root:** `/Users/abdul/Desktop/CIS`
- **OS scope:** the handout scopes this to Linux hosts, and the rubric (Part
  11) gives zero marks for other OSes — so the 10 real, evidenced rules stay
  Linux-only, full stop. The *only* concession to "works on more than Linux"
  is that `allowlist.py` and `rules.py` key every entry by
  `os_family` (default `"linux"`) instead of a flat list — see §3a. That's a
  five-minute design choice now, not a build task. Do not spend hackathon time
  writing real macOS/Windows command sets or parsers; note the extension path
  in REPORT.md §6 (Limitations/next steps) instead — that earns real marks,
  building it half-working does not.
- **Audit user:** every `docker exec` runs as `audituser` — a fixed,
  unprivileged, non-root user baked into all 3 target images by their
  Dockerfiles (see §4 Person A). Never `root`, never sudo. This is what makes
  the broken target's "permission denied" scenario *real* instead of
  hand-waved: `audituser` is deliberately left out of the `shadow` group only
  on the broken image, so reading `/etc/shadow` genuinely fails there and
  genuinely succeeds on the clean/misconfigured images. Running everything as
  root would make every check trivially readable everywhere and there'd be
  nothing to distinguish PASS/FAIL from "we didn't actually check."

---

## 1. Repo layout (create this now, before splitting up)

```
CIS/
  audit_agent/
    __init__.py
    allowlist.py        # Person A — the ONE place commands are defined
    connector.py         # Person A
    collector.py          # Person A
    rules.py               # Person B
    prioritizer.py          # Person C
    report.py                # Person C
    cli.py                    # Person C — entrypoint: audit-agent --target <container>
    fixtures/
      sample_captures.json  # Person A hand-writes this in the first 15 min
                             # so B and C never have to wait on real Docker
      sample_findings.json  # Person C hand-writes this in the first 15 min
                             # so C never has to wait on A or B either
  targets/
    Dockerfile.clean          # already scaffolded, see §4 Person A
    entrypoint-clean.sh
    Dockerfile.misconfigured
    entrypoint-misconfigured.sh
    Dockerfile.broken         # no custom entrypoint needed, see §4
  tests/
    test_collector.py       # Person A
    test_rules.py           # Person B
    test_prioritizer.py     # Person C
  WORKPLAN.md             # this file
  REPORT.md                  # written 2:40–3:00, see §7
  README.md                   # "how to run it" — Person C, mirrors REPORT.md §11
  requirements.txt
```

Nobody creates files outside this tree. If you need a new file, say so in chat
first — one-line heads-up, not a debate.

---

## 2. The data contracts (memorize these, they don't change)

There are **three** contracts. The handout only gives you two (findings, fix
list item) — you need a third for collector → rule engine, so here it is,
defined once so A and B never guess at each other's shape.

### 2.1 Command capture (collector → rule engine) — NEW, not in handout

```json
{
  "command_id": "cmd_sshd_config",
  "os_family": "linux",
  "argv": ["sshd", "-T"],
  "exit_code": 0,
  "stdout": "permitrootlogin yes\n...",
  "stderr": "",
  "status": "ok"
}
```

`status` is one of exactly two values, decided by `collector.classify()`
(full spec in §4 Person A — do not reimplement this logic ad hoc elsewhere):
- `"ok"` — the command actually ran and produced real stdout/stderr,
  **regardless of exit code**. A non-zero exit here is often the evidence
  itself (grep found nothing, a config file is legitimately absent).
- `"unavailable"` — the command could not be run at all: binary missing,
  permission denied, or timeout. `reason` (a short string) explains which.

`status != "ok"` is exactly what lets a rule resolve to `UNKNOWN` instead of
crashing or guessing.

`os_family` is fixed to `"linux"` for every command this hackathon actually
runs (see §0). It exists in the contract now purely so `allowlist.py` and
`rules.py` are keyed by it from the start — that's what makes adding a
`"darwin"` or `"windows"` command set later a config addition instead of a
rewrite. Nobody implements a second `os_family` during the 3 hours.

### 2.2 Finding (rule engine → prioritizer) — from handout Part 4, verbatim

```json
{
  "rule_id": "CIS-5.2.10",
  "title": "SSH root login disabled",
  "command": "sshd -T",
  "status": "FAIL",
  "evidence": "permitrootlogin yes",
  "severity_hint": "high"
}
```

`status` ∈ `{"PASS", "FAIL", "UNKNOWN"}`. `evidence` is always a real excerpt
of real stdout — never synthesized text.

### 2.3 Fix list item (prioritizer → report) — from handout Part 4, verbatim

```json
{
  "priority": 1,
  "rule_id": "CIS-5.2.10",
  "category": "SSH hardening",
  "finding": "Root login over SSH is permitted (permitrootlogin yes).",
  "why_it_matters": "A leaked or brute-forced root credential grants full remote access with no separate privilege step.",
  "fix_command": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
  "evidence_ref": "CIS-5.2.10"
}
```

Only **FAIL** findings become fix-list items. PASS findings are silent in the
fix list (Part 1: "a passing check earns silence, not a manufactured nitpick").
UNKNOWN findings get listed separately in the report as "could not verify" —
not silently dropped, not treated as a fix-list item.

---

## 3. The canonical 10 rules (locked — Person B implements exactly this list)

Every command here is what Person A puts in `allowlist.py`. `command_id`
values below **are** the allowlist keys — A and B both reference these, so
there is nothing to reconcile later.

| rule_id | title | command_id | argv | PASS condition | severity |
|---|---|---|---|---|---|
| CIS-5.2.10 | SSH root login disabled | `cmd_sshd_config` | `["sshd","-T"]` | no line matches `permitrootlogin\s+yes` | high |
| CIS-5.2.11 | SSH password auth disabled | `cmd_sshd_config` (reuse) | same capture | no line matches `passwordauthentication\s+yes` | high |
| CIS-5.3.1 | Minimum password length ≥14 | `cmd_login_defs` | `["cat","/etc/login.defs"]` | `PASS_MIN_LEN` present and ≥ 14 | medium |
| CIS-6.1.2 | `/etc/passwd` ownership/perms | `cmd_stat_passwd` | `["stat","-c","%U:%G %a","/etc/passwd"]` | owner `root:root`, mode `644` | medium |
| CIS-6.1.3 | `/etc/shadow` ownership/perms | `cmd_stat_shadow` | `["stat","-c","%U:%G %a","/etc/shadow"]` | owner `root:*`, mode ∈ `{640,600,000}` | high |
| CIS-6.1.10 | No world-writable files in `/etc`, `/usr/bin`, `/usr/sbin` | `cmd_world_writable` | `["find","/etc","/usr/bin","/usr/sbin","-xdev","-type","f","-perm","-0002"]` | empty stdout | medium |
| CIS-3.5.1 | Firewall active | `cmd_firewall` | `["iptables","-L","INPUT","-n"]` | policy is not `ACCEPT` **or** at least one DROP/REJECT rule present | high |¹
| CIS-2.2.4 | Automatic security updates enabled | `cmd_auto_updates` | `["cat","/etc/apt/apt.conf.d/20auto-upgrades"]` | contains `Unattended-Upgrade "1"` | medium |
| CIS-5.4.1 | No accounts with empty passwords | `cmd_empty_passwd` | `["awk","-F:","($2==\"\"){print $1}","/etc/shadow"]` | empty stdout | critical |
| CIS-5.2.9 | No blanket `NOPASSWD:ALL` in sudoers | `cmd_sudoers` | `["grep","-r","NOPASSWD","/etc/sudoers","/etc/sudoers.d"]` | no match (grep exit 1) | high |

That's 10. ¹ `iptables -L` needs `--cap-add=NET_ADMIN` on `docker run` to
read the kernel's netfilter rule table at all — but that alone is **not**
enough here, because the collector execs as `audituser`, not root (§0).
Verified live: `docker exec -u audituser <clean-container> iptables -L` still
fails with `Could not fetch rule set generation id: Permission denied (you
must be root)` even with the capability added at the container level, because
Linux only hands a container-level capability to a non-root process
automatically if it's a *file* capability on the binary, not because the
container itself has it. The fix — already baked into `targets/Dockerfile.clean`
and `targets/Dockerfile.misconfigured` — is
`setcap cap_net_admin,cap_net_raw+ep <real iptables binary>` at image build
time (the real binary is `/usr/sbin/xtables-nft-multi`; `iptables` itself is
an `update-alternatives` symlink, so `setcap` targets `readlink -f $(command -v iptables)`,
not the symlink). This was built and tested end-to-end against live
containers, not left as a guess — `docker exec -u audituser cis-clean
iptables -L INPUT -n` now correctly returns `Chain INPUT (policy DROP)`. If
you rebuild these images from scratch, keep the `setcap` line; without it the
firewall rule spuriously resolves UNKNOWN on every run regardless of your
Python code.

If a command's target *file* doesn't exist (e.g. `/etc/apt/apt.conf.d/20auto-upgrades`
was never written), that is **evidence**, not a transport failure — `cat`
still ran, it just reported "No such file or directory." `classify()` (§4)
leaves that as `status: "ok"`, and the rule resolves to FAIL ("automatic
updates not configured"), not UNKNOWN. UNKNOWN is reserved for cases where
the command genuinely couldn't be run or its output genuinely couldn't be
read — missing binary, permission denied, timeout — see §4's `classify()`
spec and §6.

If time remains after 2:15, widen this list — not before.

---

## 4. Who owns what

### Person A — Connector + Collector + Test Targets
**Owns:** `allowlist.py`, `connector.py`, `collector.py`, `targets/Dockerfile.*`,
`audit_agent/fixtures/sample_captures.json`

This is the critical path for everyone else, so A's first job (0:00–0:15) is
**not** writing real Docker code — it's hand-writing
`fixtures/sample_captures.json`: a JSON array of 10 plausible command
captures (contract §2.1) covering the misconfigured target, based on the
table in §3. This unblocks B and C immediately without waiting for real
Docker plumbing.

```python
# connector.py
AUDIT_USER = "audituser"  # baked into every target image (§0) — never root

class ConnectorError(Exception): ...

def open_session(target: str) -> "DockerSession":
    """Runs `docker exec -u audituser <target> true`. Raises ConnectorError
    if the container doesn't exist, isn't running, or `audituser` doesn't
    exist inside it (that last case means someone edited a Dockerfile without
    updating this doc — treat it as a build error, not a target problem).
    Never falls back to a default target or to root — a broken connection
    must fail loudly (Requirement 9)."""

class DockerSession:
    def run(self, argv: list[str], timeout: int = 5) -> dict:
        """Runs `docker exec -u audituser <target> <argv...>` via subprocess
        (argv passed as a list to subprocess.run, NEVER a shell string — that
        string form is the RCE hole Part 6.5 warns about). Returns
        {"exit_code": int, "stdout": str, "stderr": str, "timed_out": bool}.
        Catches subprocess.TimeoutExpired itself and sets timed_out=True
        rather than letting it propagate — collector.classify() (below)
        depends on this field being reliably set, not on catching the
        exception a second time."""
```

```python
# allowlist.py
COMMANDS = {
    "linux": [
        {"command_id": "cmd_sshd_config", "argv": ["sshd", "-T"]},
        {"command_id": "cmd_login_defs", "argv": ["cat", "/etc/login.defs"]},
        # ... all 10 from the §3 table, no more, no fewer without team sign-off
    ],
    # "darwin": [],  # NOT built this hackathon — see §0. The dict key is the
    #                # entire extension point; leave it absent, don't stub it.
}
```

```python
# collector.py
def classify(returncode: int, stdout: str, stderr: str, timed_out: bool) -> tuple[str, str | None]:
    """Pure function — no Docker, no I/O. Unit-test this directly in
    tests/test_collector.py against real stderr strings pulled off the
    broken target, don't hand-wave it. Returns (status, reason) where status
    is "ok" or "unavailable" (§2.1). Checked IN THIS ORDER:

    1. timed_out is True
       -> ("unavailable", "timed out after Ns")
    2. "executable file not found" in stderr.lower()
       or "oci runtime exec failed" in stderr.lower()
       -> ("unavailable", "binary not found in container")
       # this is docker exec itself failing to start the process — happens
       # on the broken target for cmd_firewall, since iptables isn't installed
    3. "permission denied" in stderr.lower()
       -> ("unavailable", "permission denied")
       # the process DID start (docker exec succeeded) but the command it
       # ran couldn't read something — happens on the broken target for
       # cmd_empty_passwd, since audituser isn't in the shadow group there
    4. anything else, REGARDLESS of exit code
       -> ("ok", None)
       # covers real PASS evidence AND real FAIL evidence — e.g. grep
       # exiting 1 because it found nothing, or `cat` reporting "No such
       # file or directory" for a config file that legitimately doesn't
       # exist (CIS-2.2.4's FAIL case, see §3 footnote). That distinction
       # from case 2 is exactly why "No such file" isn't pattern-matched
       # to unavailable: a missing *binary* is a transport problem, a
       # missing *config file* is audit evidence.
    """

def run_all(session: "DockerSession", os_family: str = "linux") -> list[dict]:
    """For each entry in allowlist.COMMANDS[os_family], calls session.run(argv),
    then classify()'s the result and maps it to the §2.1 capture contract
    (os_family stamped on each capture). Never raises on a single command's
    failure — only open_session() failures are fatal (Requirement 9). Also
    dumps captures to debug_raw_output.json for eyeballing (handout §6.3).
    os_family defaults to "linux" and cli.py never passes anything else this
    hackathon — the parameter exists so the extension point in §0 is real,
    not aspirational."""
```

**The 3 test targets from Part 2.3 are already scaffolded** — see
`targets/Dockerfile.clean`, `targets/Dockerfile.misconfigured`,
`targets/Dockerfile.broken` and their `entrypoint-*.sh` files, created
alongside this plan. A's job is to build and run them, not design them from
scratch:

```bash
docker build -t cis-clean         -f targets/Dockerfile.clean         targets/
docker build -t cis-misconfigured -f targets/Dockerfile.misconfigured targets/
docker build -t cis-broken        -f targets/Dockerfile.broken        targets/

# --cap-add=NET_ADMIN is REQUIRED on clean/misconfigured or every run's
# CIS-3.5.1 check spuriously goes UNKNOWN (see §3 footnote) — this is not
# optional. It works together with a `setcap` already baked into both
# Dockerfiles (needed because the collector execs as audituser, not root —
# a plain --cap-add alone is not enough for a non-root exec user, see §3
# footnote for why). Both pieces were tested together against live
# containers before this doc was written; don't drop either one.
docker run -d --name cis-clean         --cap-add=NET_ADMIN cis-clean
docker run -d --name cis-misconfigured --cap-add=NET_ADMIN cis-misconfigured
docker run -d --name cis-broken        cis-broken   # no iptables installed, cap not needed

# sanity checks before writing any Python — all verified against the real
# images as of this doc:
docker exec -u audituser cis-clean whoami                    # -> audituser
docker exec -u audituser cis-clean iptables -L INPUT -n       # -> Chain INPUT (policy DROP)
docker exec -u audituser cis-misconfigured iptables -L INPUT -n  # -> Chain INPUT (policy ACCEPT)
docker exec -u audituser cis-broken iptables -L INPUT -n      # -> exec: "iptables": executable file not found
```

What each image deliberately encodes (so B and C can read this instead of
asking "why did this rule fail on the clean target"):

| | clean | misconfigured | broken |
|---|---|---|---|
| SSH root login / password auth | disabled | **enabled** | enabled |
| Password min length | 14 | 5 | (n/a, no ssh check run) |
| `/etc/passwd`, `/etc/shadow` perms | correct | correct (untouched) | correct (untouched) |
| World-writable file under `/etc` | none | **planted** | inherited from base |
| `20auto-upgrades` | present, enabled | **absent** (FAIL evidence, not UNKNOWN) | absent |
| `iptables` binary | installed, DROP policy set at container start | installed, default ACCEPT (no rules) | **not installed** → CIS-3.5.1 = UNKNOWN, "binary not found" |
| Empty-password test account | none | **`cis_test_emptypass`** | none — but see next row |
| `audituser` in `shadow` group | yes → real evidence | yes → real evidence | **no** → CIS-5.4.1 = UNKNOWN, "permission denied" |
| Sudoers `NOPASSWD:ALL` | none | **present** | present |

The broken target intentionally carries both hostile-input cases from
handout §6.7 (missing binary, permission denied) rather than needing two
separate broken images — that satisfies Part 2.3's "partially broken target"
bullet without burning build time on a fourth Dockerfile. The third §6.7
case — target going unreachable mid-run — is tested by stopping/removing a
running container (`docker stop cis-misconfigured`) or pointing `--target`
at a name that was never built, not by anything baked into an image; that's
a `connector.py` behavior, verified in §6.

**Checkpoint gate for A:** by 0:35, `docker exec -u audituser cis-clean
whoami` must return real output through `connector.py` + `collector.py` —
this is the "one real command, real target" milestone from handout §6.2.

---

### Person B — Rule Engine
**Owns:** `rules.py`, `tests/test_rules.py`

Builds entirely against `audit_agent/fixtures/sample_captures.json` — **never
needs Docker running** to make progress. Once A's real collector output
exists (checkpoint at ~0:45–1:15), swap the fixture for the real thing and
fix whatever the real output breaks (locale differences, extra whitespace,
etc. — handout §6.3, this WILL happen, budget time for it).

```python
# rules.py
RULES = [
    {
        "rule_id": "CIS-5.2.10",
        "title": "SSH root login disabled",
        "command_id": "cmd_sshd_config",
        "severity_hint": "high",
        "parse": lambda stdout: ...,  # returns "PASS" | "FAIL", plus evidence line
    },
    # ... all 10 from §3, rule_id and command_id must match A's allowlist.py exactly
]

def evaluate(captures: list[dict]) -> list[dict]:
    """captures = collector.run_all() output (§2.1 contract).
    Returns list of Finding dicts (§2.2 contract), one per rule in RULES,
    in RULES order (this fixed order feeds the no-drift sort in §6).
    If the capture for a rule's command_id has status != "ok", the finding
    is UNKNOWN with evidence = the capture's stderr/reason. Never invents
    a PASS/FAIL when the underlying capture wasn't captured cleanly."""
```

Parsers must be boring: regex or exact-match against known lines, per handout
§6.1. Print raw evidence next to every verdict while developing and eyeball it
against the actual target config — a parser that silently matches the wrong
line is worse than a crash.

**Checkpoint gate for B:** by 1:15, `evaluate()` run against A's real captures
from the misconfigured target produces ~7-8 real FAILs and 2-3 PASSes that B
has manually verified against what's actually in the container.

---

### Person C — Prioritizer + Report + CLI (orchestration owner)
**Owns:** `prioritizer.py`, `report.py`, `cli.py`, `README.md`,
`tests/test_prioritizer.py`, final `REPORT.md` compilation

Builds `prioritizer.py` against a hand-written
`audit_agent/fixtures/sample_findings.json` (10 items, copy the shape from
§2.2 — lives right next to A's `sample_captures.json`, see §1) so C also
never waits on A or B to start.

```python
# prioritizer.py
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

REMEDIATION_TEMPLATES = {
    "CIS-5.2.10": {
        "category": "SSH hardening",
        "why_it_matters": "...",
        "fix_command": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
    },
    # ... one entry per rule_id in §3, this is the deterministic engine —
    # it alone is sufficient to pass, per handout Part 12 FAQ
}

def prioritize(findings: list[dict]) -> list[dict]:
    """Filters to status == "FAIL" only. Looks up each in
    REMEDIATION_TEMPLATES. Sorts by (SEVERITY_ORDER[severity_hint], rule_id)
    — rule_id as tiebreak is what makes ordering deterministic across runs
    (handout Part 5). Assigns priority = 1..N after sorting. Every item's
    evidence_ref == its rule_id, satisfying Requirement 5."""
```

```python
# report.py
def build_report(findings: list[dict], fix_list: list[dict], meta: dict) -> dict:
    """meta = {"target": str, "timestamp": str, "transport": "docker"}.
    Returns the report.json structure: findings, fix_list, unknowns
    (findings with status UNKNOWN, listed separately, not silently dropped),
    and a summary count of PASS/FAIL/UNKNOWN."""

def render_markdown(report: dict) -> str:
    """Human-readable report.md: summary counts at top, then fix list in
    priority order, then full findings table, then UNKNOWNs with reasons."""
```

```python
# cli.py
# Entrypoint: python -m audit_agent.cli --target <container_name>
# Wires: connector.open_session -> collector.run_all -> rules.evaluate ->
# prioritizer.prioritize -> report.build_report -> writes report.json +
# report.md. If open_session() raises, exit(1) with the error on stderr —
# nothing else runs (Requirement 9). All other command-level failures are
# caught inside collector and surfaced as UNKNOWN, never crash the run.
```

**LLM stretch (only after everything above is committed and working, and only
if organisers confirm it's permitted):** add an optional path in
`prioritizer.py` gated by `--llm`, that sends `findings` (never raw captures,
never credentials) to a model with temperature 0, gets back JSON in the exact
§2.3 shape, and — critically — cross-checks the returned `fix_command` for
each rule_id against `REMEDIATION_TEMPLATES` before accepting it. The
deterministic engine stays the default and the fallback if the LLM call
times out or returns malformed JSON.

**Checkpoint gate for C:** by 1:45, running `cli.py` twice in a row against
the same unchanged container produces byte-identical `report.json` except for
the timestamp field. This is Requirement 6 / Part 5 and is worth 10 marks
with **zero partial credit** — verify it explicitly, don't assume it.

---

## 5. Timeline (mirrors handout Part 8 — timekeeper calls these out)

| Time | Everyone | A | B | C |
|---|---|---|---|---|
| 0:00–0:15 | Read this doc, confirm §2/§3 contracts, assign roles | Hand-write `fixtures/sample_captures.json`; kick off `docker build`/`docker run` for all 3 targets in the background | Wait for fixture (~5 min) | Hand-write `fixtures/sample_findings.json` |
| 0:15–0:45 | Parallel build | Real `connector.py`+`collector.py` against real `docker exec` on clean+misconfigured targets; build `targets/Dockerfile.*` | Build `rules.py` fully against the fixture | Build `prioritizer.py` + `report.py` against hand-written findings |
| 0:45–1:15 | **Integration checkpoint 1** | Hand real captures to B | Swap fixture for A's real output, fix parser mismatches | Keep building report.py / cli.py skeleton |
| 1:15–1:45 | **Integration checkpoint 2** | Support A/B integration issues | Findings verified against real misconfigured target | Wire full pipeline in `cli.py`, run end-to-end for the first time |
| 1:45–2:15 | No-drift + hostile input | Add UNKNOWN handling for `targets/Dockerfile.broken` (missing binary, permission denied, timeout) | Confirm rules resolve UNKNOWN cleanly, no crashes | Verify 2 runs = identical JSON except timestamp; verify non-zero exit when target unreachable |
| 2:15–2:35 | **Everyone reviews `allowlist.py` + `collector.py` together** — confirm zero mutating commands, zero string-built commands, credentials only from env | | | |
| 2:35–2:40 | **BUILD FREEZE** — commit and push | | | |
| 2:40–3:00 | REPORT.md (see §7) | writes §7.3 connector/collector row + 2 results rows | writes §7.2 rule set section in full | compiles doc, writes results table, "how we worked," "how to run it" |

---

## 6. No-drift + hostile-input checklist (Parts 5–7 of the handout — zero partial credit on drift)

Before 2:35, confirm as a group:
- [ ] Two runs on the unchanged misconfigured container → identical `report.json` except timestamp
- [ ] Fix list order is stable (severity, then rule_id tiebreak — not insertion order, not a set/dict iteration order)
- [ ] `cis-broken`: `iptables` missing → CIS-3.5.1 is UNKNOWN, reason "binary not found in container", run doesn't crash
- [ ] `cis-broken`: `audituser` not in `shadow` group → CIS-5.4.1 is UNKNOWN, reason "permission denied", not a fabricated PASS
- [ ] `cis-clean`/`cis-misconfigured` were started with `--cap-add=NET_ADMIN` → CIS-3.5.1 resolves PASS/FAIL there, not a spurious UNKNOWN
- [ ] A container name that was never built, and a container stopped mid-run (`docker stop cis-misconfigured`) → both make `cli.py` exit non-zero immediately via `ConnectorError`, nothing downstream runs
- [ ] No command anywhere is built by string concatenation/interpolation — every `argv` is a literal list from `allowlist.py`
- [ ] No credential or API key is hardcoded anywhere — grep the repo before freeze

---

## 7. REPORT.md ownership (write 2:40–3:00, 20 min, no more)

Structure exactly per handout Part 9. Assign:
1. **What we built / architecture** — C drafts, everyone reviews for 2 min
2. **The rule set** (all 10 rules, command, parser logic) — B, full ownership
3. **Methods** (transport chosen/rejected, allowlist design, read-only
   enforcement, static-vs-LLM decision) — A writes transport+allowlist rows,
   C writes the LLM-decision row
4. **Results** — table of ≥6 real runs across clean/misconfigured/broken —
   A and B each contribute 3 rows from their own testing, with honest notes
   on any false positive/negative
5. **How we worked** — planned vs actual per §5 checkpoint, one abandoned
   dead end — whoever hit one writes it, C compiles
6. **Limitations and next steps** — specific, not "add more checks" — e.g.
   "sudo-gated evidence gathering for `/etc/shadow` on the broken target
   needs a documented elevation path we didn't build"
7. **How to run it** — C, must work standalone from this section alone

Commit `REPORT.md` and everything else by 2:40. **Nothing edited after 2:40
counts** — the handout is explicit that uncommitted work does not exist.
