# cloud.md — Kharibulbul SIEM project log

This file is the running record of the project: what exists, why it was built that way, how it
was verified, and what is still open. **Every working session appends a dated entry below and
refreshes the "Current state" section** (see `CLAUDE.md`). Read it first when you come back.

---

## Current state (as of 2026-10-05, session 6 — server + both agents running)

| Item | Status |
|------|--------|
| Codebase | **v1.0.0 + session-5 features** – agent, ingest (TCP/TLS/mTLS, syslog, HTTP), 10 parsers, schema + **ECS conformance layer** (`common/ecs.py`), enrichment (+time context, **GeoIP country table**), SQLite+FTS5 store (**no retention by default**), query language (incl. `field:(a OR b)`), rule engine, alerting (console/file/webhook/SMTP, **escalation**), API, dashboard (date-range search, **Add-agent wizard**, **rule editor**, **playbook editor**), CLI (+`geoip`, `alerts escalate`), simulator (`kharibulbul/`, ~8,000 lines Python) |
| Detection content | **95 shipped rules** in 20 files (`rules/`, incl. 18 team rules in `rules/team/`), all MITRE-mapped, all linked to one of 9 playbooks; custom rules/playbooks written in the dashboard live in `custom/` (none yet) |
| Scenarios | **52 safe scenarios** (`simulate/scenarios.py` + `simulate/coverage_pack.py`), 671 log records, no tooling; events are marked with `labels.simulation` (was `simulation`) |
| Validation matrix | `docs/reports/WEEK3-VALIDATION.md` (regenerated 2026-09-30): 94/95 rules fired by ≥1 scenario, baseline quiet (only KB-KB-002 not simulated, by design); result no longer depends on the time of day (KB-NET-032 fix) |
| Tests | **123 pytest tests**, all passing (`python -m pytest -q`, ~20 s); 25 added 2026-09-30 (agent shipper/spool, `su` parser, `tests/test_features.py`, stale-dashboard test) |
| Rule validation | `python -m kharibulbul rules validate rules` → 95 checked, 95 loadable, 0 problems |
| Live verification | agent on this PC (real Windows channels + file), outage/spool/replay test, TLS + mTLS + wrong-secret rejection, webhook delivery (5/7 filtered by severity), tabletop triage – all on 2026-09-27; clean demo run 2026-09-28: 676 events → 147 alerts for 94 rules, 0 rule errors; **real agents** 2026-09-28: `win-laptop` (Windows, this PC) and `ubuntu-wsl` (Ubuntu 26.04 in WSL 2) online, Linux activity → 10 alerts through the real path; **2026-09-30**: both agents live again, every session-5 feature exercised on the running server (API round trips + headless-Chrome run through all new UI flows, 0 JavaScript errors); **2026-10-05**: server started (`/api/health` 200); **both demo agents online** — `win-laptop` (127.0.0.1:5044, System/Application/PowerShell/Defender/RDP/Firewall/BITS) and `ubuntu-wsl` (journald → 172.20.32.1:5044) |
| Reports | `docs/reports/WEEK1-REPORT.md`, `WEEK2-REPORT.md`, `WEEK3-VALIDATION.md`, `WEEK3-TABLETOP.md`, `WEEK4-REPORT.md`, `FINAL-REPORT.md` (v1.0); `docs/TUNING-LOG.md`, `docs/INCIDENTS.md` |
| Docs | `README.md`, `GUIDE.md`, `CLAUDE.md`, `docs/*` (architecture, schema, query language, rules, operations, lab setup, week 1–4 plans, team roles, presentation), `playbooks/`, `dashboards/`, `intel/`, `geoip/`, `samples/` |
| Lab deployment | scripts written and syntax-checked; **not executed on lab VMs yet** (team) |
| Agents (demo) | `config/agent-windows-host.yml` (Windows, no admin) + `config/agent-linux-wsl.yml` with `scripts/wsl-agent.sh` (setup/run/activity); `run-dev.ps1 -WindowsAgent / -WslSetup / -WslAgent / -WslActivity` |
| Explainer (AZ) | `Kharibulbul-SIEM-Izahat.docx` (repo root): every component explained + session-4 work, in Azerbaijani |
| Git | repository not initialised yet (team decision) |
| Demo data | `data/` holds the 2026-09-28 demo DB; the session-2 DB with the tabletop alerts is archived in `data/archive/2026-09-27-session2/` |
| GeoIP data | `geoip/dbip-country-lite.csv.gz` (DB-IP IP to Country Lite 2026-09, CC BY 4.0, 4.5 MB, 357k IPv4 + 360k IPv6 ranges) downloaded 2026-09-30; refresh with `kharibulbul geoip update` |
| Environment (this PC) | Python 3.12.10 at `C:\Users\085.PC\AppData\Local\Programs\Python\Python312\python.exe`; **`.venv` present** (used by `scripts\run-dev.ps1`); package editable; Git Bash + openssl available; not elevated; Node 24 + Chrome (used for UI checks); WSL 2 `Ubuntu` distro (26.04, systemd, hostname `ubuntu-wsl`, users `root`, `user1` (default, sudo), `user2`) |

### How to run (reminder)
```
.\scripts\run-dev.ps1              # server  -> http://127.0.0.1:8080/
.\scripts\run-dev.ps1 -Simulate    # synthetic scenarios -> alerts
.\scripts\run-dev.ps1 -Tests       # pytest
python -m kharibulbul rules coverage --out docs\reports\WEEK3-VALIDATION.md
```

### Open items / next steps
1. Team: build the isolated lab VMs and run the install scripts (`docs/WEEK1.md`); real Sysmon/Security telemetry; screenshots with real data.
2. Team: `git init`, commit, tag `week1`… `v1.0`.
3. Optional: MaxMind GeoLite2 file (city level; country level now works without it); OpenSearch mirror + one OpenSearch Dashboards visualisation; SMTP sink test with a lab mail server.
4. Team decisions left from session 5: triage the KB-PS-001 alerts (IDE/CLI PowerShell wrappers) and KB-LNX-014's title ("to root" but matches any target); the Azerbaijani Word explainer and `docs/reports/FINAL-REPORT.md` do not describe the session-5 features yet; `user.name` values with quotes (`'user1'`) come from a journald line the syslog parser does not strip.
5. Keep this file updated every session.

---

## Session log

### 2026-10-05 — Session 6: scan and start the project

User asked to scan the repo and run it.

**Scan.** Layout matches GUIDE: `kharibulbul/` (~60 Python modules), 95 rules in 20 YAML files, 52 scenarios, SQLite demo DB in `data/`, dashboard static UI. `python -m kharibulbul rules validate rules` → 95 checked, 95 loadable, 0 problems. `python -m pytest -q` → **123 passed** (~20 s). Ports 8080 / 5044 / 5514 were free.

**Run.** First start failed on this Windows console: `UnicodeEncodeError` (cp1252) printing the ASCII-art banner (`Xarıbülbül` contains U+0131). Fix in `kharibulbul/server/main.py`: reconfigure stdout/stderr to UTF-8 with replace, and a fallback `_print_banner`. Second start succeeded: agent ingest `0.0.0.0:5044`, syslog UDP `0.0.0.0:5514`, web UI `http://127.0.0.1:8080/`. Health `status=ok` v1.0.0. Dashboard Overview showed 3,078 stored events (46.3 MB, since 2026-09-28), 0 open alerts in the last 24 h, 0/2 agents online (Windows/WSL agents not launched this session). Left **running**.

**Open.** Same lab/git items as session 5. To fill alerts: `.\scripts\run-dev.ps1 -Simulate`. Server + both agents left running.

### 2026-10-05 — Session 6 (continued): agents started

User asked to run the agents. Windows: `python -m kharibulbul agent -c config\agent-windows-host.yml` → `win-laptop` connected to 127.0.0.1:5044. Linux: `wsl -d Ubuntu -u root bash scripts/wsl-agent.sh run` (Ubuntu was Stopped; booted) → `ubuntu-wsl` connected to 172.20.32.1:5044 (NAT gateway). `/api/agents`: both `online` (`win-laptop` 192.168.0.66, `ubuntu-wsl` 172.20.33.204). Left running with the server.

### 2026-09-30 — Session 5 (end): everything stopped on request

"You can stop it now." Linux agent stopped with SIGINT (clean exit) and its console window closed;
Windows agent stopped, bookmark check: 0 undelivered records on all 7 channels; server stopped with an
empty write queue (3,077 events stored, 22 open alerts, DB 47.9 MB + WAL). No Kharibulbul process is
left and ports 8080 / 5044 / 5514 are free (rule 4 satisfied). Left alone: the Ubuntu distro and the
user's own Ubuntu shell window (`user1`). The earlier "left running" notes in this session's entries
no longer apply. Next start: `python -m kharibulbul server -c config\server.yml`, then
`.\scripts\run-dev.ps1 -WindowsAgent` / `-WslAgent` (or the commands in the entries below).

### 2026-09-30 — Session 5 (continued): API docs menu entry hidden

The user asked (in Azerbaijani) what the *API docs* menu entry is for, then to hide it. The link was
removed from the sidebar (`web/static/index.html`); `/api/docs` and `/api/openapi.json` still work when
opened directly. No server restart needed (the page is read per request; the build id changes, so open
tabs show the reload bar). GUIDE and README note that the docs have no menu entry. Verified live: the
served page no longer contains the link, `/api/docs` answers 200, pytest 123 passed.

### 2026-09-30 — Session 5 (continued): "not possible to add any agent, rule" — stale dashboard in the browser

**Report.** After the feature work the user could not add an agent, a rule or a playbook.

**Cause.** Nothing was wrong on the server (healthy, no errors, the served `app.js` had the new
buttons, the API round trips worked). The static files were sent **without `Cache-Control`**, so Chrome
applied heuristic freshness: the `app.js` it had loaded at 19:18 (last modified 3 days earlier) counted
as fresh for about 7 hours, and a normal reload only revalidates the page, not its scripts. The user's
tab was still running the pre-feature script. My earlier "refresh with Ctrl+F5" note was the only
thing standing between the user and the new UI — not good enough. (My headless-Chrome check used a
fresh profile, so it could not see this.)

**Fix.** `server/api.py`: every static response carries `Cache-Control: no-cache` (`_NoCacheStatic`);
`/ui/` and `/ui/index.html` are served by a route that links the assets as `app.js?v=<build>` /
`style.css?v=<build>` (`ui_build()` = version + newest file mtime) and is `no-store`; `/` redirects to
`/ui/?v=<build>`; `/api/health` reports `ui`. `app.js` compares its own build with the server's every
30 s and shows an "updated on the server — Reload now" bar when they differ. New test
`test_dashboard_is_never_served_stale`.

**Verification.** pytest **123 passed**, rules 95/95, `node --check`. Server restarted (queue 0, both
agents back online by themselves); headers confirmed live; the headless run through add-agent, rule and
playbook flows repeated: no JavaScript errors, no residue. The Agents page was opened for the user at
the versioned address. Not verifiable from here: that the user's own tab now shows the buttons.

### 2026-09-30 — Session 5 (continued): eight dashboard / pipeline features

**Ask (7).** A pasted list in Azerbaijani, taken as the task: (1) remove the date limit — only a 30-day
investigation was possible — and search logs by date; (2) an escalate function for alerts; (3) add a new
agent from the Agents tab, with a guide there; (4) show agent IPs in the Agents tab; (5) write custom
rules in the Rules tab; (6) add our own playbooks; (7) fix the GeoIP function → geo-IP enrichment;
(8) ECS-style normalisation.

**1 · Date limit.** Two limits existed: the UI range picker stopped at 30 d and
`store.retention_days: 30` purged older events hourly. Now retention defaults to **0 = keep
everything** (`config/server.yml`, `SERVER_DEFAULTS`); the API accepts `from=all` (since the oldest
event) next to relative values and ISO dates, rejects `to <= from`, and `_interval_for` scales buckets
up to a year; the UI range picker (Overview, Events, Alerts) has 90 d / 1 y / all plus exact from–to
`datetime-local` inputs and redraws itself without resetting the page's filters. Found on the way: the
Events pager's buttons were always disabled (`el()` set `disabled="null"`) — fixed.

**2 · Escalation.** New status `escalated` (still open: `store.OPEN_STATUSES`). `AlertManager.escalate()`:
level 1→3 (default recipients Tier 2 analyst → SOC lead / incident responder → Incident manager),
severity one step up unless told otherwise, `escalation{}` + history entry, notification on every
enabled sink (`Notifier._dispatch_escalation`). `POST /api/alerts/{id}/escalate`, PATCH with
`status: escalated`, CLI `alerts escalate`, UI section in the alert drawer + status filter + banner +
history table + Reopen button.

**3 + 4 · Agents.** `server/enroll.py` + `GET /api/agents/enroll/info`, `POST /api/agents/enroll`,
`DELETE /api/agents/{id}`: the wizard issues the agent id (new config key `agent.id`), stores the agent
as `pending`, returns `agent-<name>.yml` for one of four profiles and a per-system install guide
(6–9 steps with commands). `local_ips()` rewritten: address facing the server first (UDP-connect
trick), default route, other interfaces, link-local last — the WSL agent used to report **no** IP
(its hostname resolves to 127.0.1.1). Agents page: IP column (primary bold, others as tags), "connected
from", pending status, remove button, "how an agent is added" card.

**5 + 6 · Custom rules and playbooks.** `server/content.py` (`CustomContent`): stored under `custom/`
(`custom_dir`), one rule per file, shipped content read-only, ids/names cannot collide, size limits,
safe names. `validate_rule` now also runs `matchers.check_selection` (unknown modifiers, regexes,
CIDRs, numbers) — all 95 shipped rules pass. API: `GET /api/rules/template`, `POST /api/rules`,
`PUT|DELETE /api/rules/{id}`, `POST /api/playbooks`, `PUT|DELETE /api/playbooks/{name}`. UI: rule editor
(template, Validate & test against pasted lines, save, edit, delete, clone a shipped rule), playbook
editor with live preview. `renderMarkdown` now only emits http(s)/relative links (user-written
Markdown). Decision: custom content is **not** put into `rules/` / `playbooks/`, so the curated set
(95 rules, scenario coverage, playbook tests) stays intact.

**7 · GeoIP.** Before: only 11 hand-written ranges, every other public address was "Unknown" (no
MaxMind file). Now `geoip/dbip-country-lite.csv.gz` (DB-IP Lite, CC BY 4.0, downloaded from
download.db-ip.com) is read by our own `CountryDB` (arrays + bisection, IPv4 and IPv6, 1.6 s load,
cross-checked against 2,050 rows of the file: 0 mismatches); `pipeline/countries.py` gives names and
continents. Order: custom CSV → private/lab → MaxMind (optional) → country table. CLI `geoip
update|lookup|status`, `GET /api/geoip/lookup`, `/api/stats.geoip`, Overview panel "Destination
countries". Lab zones' pseudo country code `LAB` → `XL` (ISO user-assigned, two letters).

**8 · ECS.** `common/ecs.py`: `conform()` in the normaliser (`ecs.version` 8.11.0, allowed-value
mapping, `related.hosts/hash`), `validate()` after enrichment (tag `ecs-nonconformant` +
`kharibulbul.ecs.problems`), `to_nested()` for `?format=ecs`, the event drawer, ECS JSON export,
`parse --ecs/--check` and the OpenSearch mirror. First validation run: 671/860 documents failed only
on `simulation` (now `labels.simulation`) and `LAB` (now `XL`); after the fixes 860/860 conform.

**Verification.** pytest **122 passed** (16 new in `tests/test_features.py`); `rules validate` 95/95;
coverage matrix regenerated (94/95, baseline 0); `node --check app.js`. Live on the restarted server:
date search (`all` = 2,677 events, 2026-09-28 only = 220), GeoIP lookups, enrol/delete an agent,
create/delete a rule and a playbook, `format=ecs` — no residue left. A headless-Chrome script drove
the UI through every new flow (add agent, new rule → test → save → edit → delete, clone, new playbook
→ save → delete, alert drawer, date search, ECS view): **no JavaScript errors**; screenshots checked.
Not done live: escalating one of the user's real alerts (covered by tests only).

**Restarts.** Server restarted twice (kill, queue 0 both times). Linux agent restarted with SIGINT in
a new console window (now reports 172.20.33.204). Windows agent killed and restarted; the bookmark
check showed 0 undelivered records. All three are running again (rule 4 exception, user's request).

**Docs.** GUIDE (agent enrolment, ECS, GeoIP, no date limit, escalation, API table, dashboard, CLI,
config, tests), README, `docs/SCHEMA.md`, `RULES.md`, `OPERATIONS.md`, `ARCHITECTURE.md`,
`geoip/README.md`, `custom/README.md`, `CLAUDE.md`.

### 2026-09-30 — Session 5: server + both agents started; shipper line-limit fix

**Ask (2).** "Run agents." Both started in the background: `win-laptop`
(`python -m kharibulbul agent -c config\agent-windows-host.yml`) and `ubuntu-wsl`
(`wsl -d Ubuntu -u root bash scripts/wsl-agent.sh run`, server reached through the NAT gateway 172.20.32.1).

**Bug found (agent livelock).** The Windows agent resumed from its 2026-09-28 bookmark, delivered 600
backlog events and then built a 100-event batch of **1.1 MB** (PowerShell 4104 script-block events up to
45 kB each). That is above the server's `ingest.max_line_bytes` (1 MiB): the server answered
`line too long`, the agent spooled the batch, reconnected at once and replayed the same file —
a tight reconnect loop with no back-off (2,457 rejected lines in under a minute), nothing delivered any more.

**Fix.** `kharibulbul/agent/shipper.py`: `_deliver()` splits a batch into protocol lines of at most
`batch.max_bytes` (new key, default 524288); a single envelope above the limit is sent with `raw` cut
short (`...[truncated by agent]`); a `line too long` reply halves the limit for the retry; a rejected
send now goes through the reconnect back-off (back-off resets on ack/pong, not on connect).
`kharibulbul/agent/spool.py`: `drain()` takes a sender that returns the number of delivered events and
rewrites a partly delivered file with its rest (event ids are assigned server-side, so re-sending a
whole batch would duplicate). `common/config.py`: default `batch.max_bytes`. New
`tests/test_agent_shipper.py` (7 tests, fake line-limited TCP server). GUIDE § shipper/config/testing
and README test count updated.

**Recovery.** The looping agent had to be killed (no graceful stop for a background process on
Windows), which dropped its in-memory queue while the bookmark file was already ahead. Bookmarks in
`data/agent-windows-host/agent-state/winlog-0.json` were rewound per channel to the last record that
was stored on the server or in the spool (channels with nothing stored: to the previous agent stop,
2026-09-28 18:06 UTC); 953 records re-read. After the restart the spool replayed (100 events,
split below the line limit), and for all 7 channels the server's highest `winlog.record_id` equals the agent bookmark — no
gap, no duplicates, 0 rejected lines since the fix. The WSL agent was stopped with SIGINT (clean
exit) and restarted on the fixed code.

**Verification.** `python -m pytest -q` → **105 passed**; `rules validate` → 95/95, 0 problems (no
rule/scenario change, coverage matrix not regenerated). Live: both agents `online`, store 75 → 1,837
events, 0 rule errors. Alerts raised from real telemetry: KB-WIN-031 ×6 (new services in the System
log), KB-KB-001 ×2 (both agents silent since 2026-09-28, raised at server start), KB-PS-001 ×3 new
(one with 46 hits) — the sample events are 4104 script blocks of **developer tooling on this PC**
(the PowerShell wrappers of Cursor and Claude Code, `$EncodedCommand = '...'`, 2026-09-29/30, this
session's own commands included); not triaged further, most likely benign.

**Ask (3, 4).** "Turn on linux agent" / "pop the window up": the agent was already online in the
background; it was stopped with SIGINT and restarted in its own console window (`cmd /k` titled
"Kharibulbul - Linux agent (ubuntu-wsl)" running `wsl -d Ubuntu -u root bash scripts/wsl-agent.sh run`),
online again within seconds. Ctrl+C in that window stops it.

**Ask (5).** "Let me work on linux agent": an interactive Ubuntu shell window was opened
(`wsl -d Ubuntu -u root` in a `cmd /k` window). Because the distro had only ever been started
non-interactively, this first interactive launch ran Ubuntu's first-run setup: a user **`user1`**
(uid 1000, groups sudo/adm/…) was created at 19:37 local, `/etc/wsl.conf` got `[user] default=user1`,
and the window is a `user1` shell, not root. The project scripts are unaffected (they pass `-u root`).
The running agent shipped that activity and the server raised KB-LNX-012 (new account), KB-LNX-011 ×2
(added to sudo/adm) and KB-COR-003 (critical: account created then added to a privileged group) — real
detections of a real, benign admin action.

**Ask (6).** "Create user2 (password pass1111) so I can switch users; a mistyped password must raise
the Overview's authentication failures." `useradd -m -s /bin/bash user2` + `chpasswd` in the Ubuntu
distro (uid 1001, no sudo). Testing `su - user2` from `user1` showed the counter was wrong: one
successful switch +1, one mistyped password +2 (see `docs/TUNING-LOG.md`). `parse_su()` in
`pipeline/parsers/syslog.py` rewritten with explicit patterns (`su-failed`, `su-success`,
`su-pam-auth-failure`, `su-session-opened/closed`, `su-message`); KB-LNX-014 now matches `su-failed`
or `su-pam-auth-failure`; new `test_su_switch_user` with the real journal lines. pytest **106 passed**,
rules 95/95, coverage matrix regenerated (94/95, baseline 0). Server restarted (the background process
can only be killed; store queue was 0, agents reconnected by themselves). Live check after the
restart: correct password → failures +0, one wrong password → +1 (a second +1 in the same minute was
the user's own attempt from `pts/2`). Events stored before the fix keep their old classification
(2 bogus failures from the 19:43 test stay in the 24 h counter until they age out).

**Open.** Server (8080/5044/5514) and both agents were left running at the user's request (rule 4
exception) — stop them when done. KB-LNX-014 is titled "Failed su to root" but fires for any target
account (team decision: restrict or rename). The team should triage the three KB-PS-001 alerts and, if they are
the IDE/CLI wrappers, record a tuning entry in `docs/TUNING-LOG.md`.

**Ask (1).** "Run this app."

**Done.** `rules validate` → 95 checked, 95 loadable, 0 problems. Server started with the system
Python 3.12 (`python -m kharibulbul server -c config\server.yml`; no `.venv` exists, so `run-dev.ps1`
would have created one — not needed, the package is installed editable). Existing demo DB in `data/`
reused, nothing deleted.

**Verification (live).** `/api/health` ok (v1.0.0); `/` → `/ui/` serves `index.html`, `app.js`,
`style.css`, `favicon.png`, `logo.png` (all 200); `/api/stats`: 95 active rules, 0 rule errors, store
75 events (2026-09-28 demo data + this start); `/api/alerts/summary`: 1 open alert (KB-PS-001, from
session 4); `/api/agents`: `win-laptop` and `ubuntu-wsl` registered but **disconnected** (agents not
started this session). Listeners: 5044 (agents), 5514/udp (syslog), 8080 (API + UI). Dashboard opened
in the default browser.

### 2026-09-28 — Session 4: new logo, Windows + WSL Linux agents, Word explainer

**Ask.** "Replace the logos with the new `logo.jpg`; using WSL create one Linux and one Windows agent;
finally prepare a Word file explaining how it was done and what every part of the SIEM does."

**Logo.** `logo.jpg` (360×360, white background) → Pillow: near-white pixels made transparent (edges
kept), cropped, square canvas → `kharibulbul/web/static/logo.png` (319×319) + `favicon.png` (64×64).
`index.html` (img + favicon), `api.py` (`/logo.svg` → `/logo.png`, image/png), README / GUIDE /
CLAUDE.md descriptions updated; the old hand-drawn SVG archived as `docs/assets/logo-v1.svg`; the
original `logo.jpg` stays in the repo root. Server restarted: `/logo.png` 200 image/png, `/ui/` uses it.

**Windows agent (this PC).** Channels readable without elevation tested with `wevtutil`: System,
Application, PowerShell/Operational, Windows Defender/Operational, TerminalServices-LocalSessionManager,
Windows Firewall With Advanced Security, BITS-Client (Security denied, Sysmon absent, TaskScheduler
empty; `eventcreate` denied too). New profile `config/agent-windows-host.yml` (agent `win-laptop`,
`start: now`, data under `data/agent-windows-host/`), started in its own console window
(`run-dev.ps1 -WindowsAgent`): online within seconds; datasets this session windows.powershell 62,
windows.system 22, windows.firewall 15 (every PowerShell console yields 40961/40962/53504/4104).

**Linux agent in WSL 2.** WSL 2.7.13 had only `docker-desktop`. `wsl --install -d Ubuntu --no-launch`
needed no elevation (Ubuntu 26.04.1 LTS, Python 3.14.4, PyYAML present, systemd on); the first,
hidden background attempt hung silently, the foreground one downloaded ~420 MB and finished.
`scripts/wsl-agent.sh setup|run|activity`: *setup* ensures python3-yaml, `systemd=true` and
`hostname=ubuntu-wsl` in `/etc/wsl.conf` (WSL otherwise reports the Windows hostname and both agents
collapsed into one host; `wsl --terminate Ubuntu` once); *run* probes 127.0.0.1 → NAT gateway →
resolv.conf nameserver on :5044 and exports `KB_SERVER_HOST` (172.20.32.1 here; the Windows firewall
did not block WSL → host); *activity* = benign useradd/usermod/userdel/sudo + `logger` sshd/sudo lines
(same content as the `ssh-brute-force` scenario) into the local journal. Profile
`config/agent-linux-wsl.yml`: **journald input only** — Ubuntu's image also runs rsyslog, and the
initial extra `/var/log/auth.log` file inputs shipped every line twice (removed; a `logger` test line is
now stored exactly once). Result: `ubuntu-wsl` online from 172.20.33.204, datasets linux.system /
linux.auth / linux.journald / linux.firewall; the activity produced 10 alerts over the real path
(KB-COR-002, KB-COR-003 critical; KB-LNX-001/005/011/020 high; KB-LNX-002/004/017 medium; KB-LNX-012 low).

**Launcher and docs.** `run-dev.ps1` gained `-WindowsAgent`, `-WslSetup`, `-WslAgent`, `-WslActivity`;
GUIDE § 2, § 5 ("Two agents on one laptop"), § 17; README quick start; CLAUDE.md commands / layout /
environment.

**Word explainer.** `Kharibulbul-SIEM-Izahat.docx` (repo root, Azerbaijani, built with docx-js):
project summary and numbers, architecture and component table, every component explained (§ 3.1–3.11),
this session's work step by step with the findings above, results tables, demo sequence, limitations.
24 headings, 8 tables, logo embedded; OOXML-validated (no LibreOffice/Word on this PC to render it).

**UI tweak (user request).** The tri-colour bar at the bottom of the sidebar now runs green – red – blue from left to right (was blue – red – green): `nav.side .tri` in `style.css`; static file, no restart needed (hard-reload the page).

**Clean real-data view (user request).** Server stopped, the demo DB + `alerts.jsonl` moved to `data/archive/2026-09-28-demo/`, server restarted on an empty DB; both agents reconnected by themselves (spool replay) and no scenario was sent, so the dashboard now holds real Windows/WSL telemetry only. Re-run `simulate all` any time to bring the scenarios back.

**Verification.** pytest 98/98; `rules validate` 95/95, 0 problems; `/api/agents` shows both agents
online; `detect.errors = {}`. Server, Windows agent and WSL agent ran in their own console windows for the demo and were
stopped at the end of the session (all three processes, their consoles and the Ubuntu distro; no ports left open).

**Environment notes.** Pillow, defusedxml/lxml (pip) and `docx` (npm, session scratchpad) installed;
Ubuntu WSL distro added (user-level). Nothing needing elevation was done.

### 2026-09-28 — Session 3: release 1.0.0, consistency pass, clean demo run

**Ask.** "Continue where you left off, finalise the project and run it so I can look."

**State check.** pytest 98/98, `rules validate` 95/95, no leftover background processes, every
session-2 deliverable present. The remaining open items are team-only (lab VMs, git).

**Finalisation.**
* Version **1.0.0** in `kharibulbul/__init__.py` and `pyproject.toml` (GUIDE header, `/api/health`,
  server banner follow; editable-install metadata refreshed). `FINAL-REPORT.md` retitled v1.0;
  README reference updated.
* Numbers reconciled with what the tools measure today: `simulate all` = 671 events (docs said
  806 / ~800 / 245), `docs/PRESENTATION.md` slide 3 (77+ rules / 16 scenarios / 52+ tests → 95 / 52 / 98,
  10 parsers) and slide 15 (auditd/DHCP parsers exist now), `docs/ARCHITECTURE.md` throughput line
  (77 → 95 rules), GUIDE quick start and § 23 test count. `CLAUDE.md` status snapshot rewritten (it
  still listed session-2 work as pending).
* Found during the live run: **KB-NET-032** (new DHCP lease outside business hours) fired in the
  22:38 coverage run of 2026-09-27 but not in the 13:03 `simulate all` today (93/95) — the `dhcp`
  scenario stamped its leases with the current time. Fix: one more lease record pinned to 22:30 UTC
  (02:30 lab time) like `after-hours-logon`; `EXPECTED["dhcp"]` includes KB-NET-032; entry in
  `docs/TUNING-LOG.md`. Matrix regenerated: 94/95, baseline 0, 671 events, independent of the clock.

**Demo run (left running for the user).** Session-2 DB archived to `data/archive/2026-09-27-session2/`;
server started in its own console window (`python -m kharibulbul server -c config\server.yml`,
v1.0.0 banner); browser opened on <http://127.0.0.1:8080/>; `simulate all` + `simulate dhcp` →
676 events stored, **147 alerts** (14 critical, 98 high, 27 medium, 8 low) for **94 distinct rules**,
`detect.errors = {}`, all parsers exercised (windows 391, syslog 163, web 67, winfirewall 20,
auditd 14, apache_error 10, windows_dhcp 9, json 2); console and `data/alerts.jsonl` sinks delivered.
Stop it with Ctrl+C in that window or `Stop-Process` on the python process listening on :8080.

**Verification.** pytest 98/98 · `rules validate` 95 checked, 0 problems · `rules coverage` 94/95,
baseline 0 · live API checks (`/api/health`, `/api/stats`, `/api/alerts`, `/api/dashboard/overview`, `/ui/`).

**Open items.** Unchanged: team runs the install scripts on the isolated lab VMs, collects real
Sysmon/Security telemetry and screenshots, `git init` + tags; optional MaxMind / OpenSearch / SMTP.

### 2026-09-27 — Session 2: the four weekly plans executed for real

**Ask.** "Complete all 4 weeks" – produce the deliverables and evidence the weekly plans assign to
the team, not just the plans. Everything below was run on this PC (Windows 11, non-elevated).

**Week 1 – stack, agents, Sysmon.**
* Local end-to-end run: `config/agent-local-test.yml` (winlog System/Application/PowerShell + file
  input) against the server; agent `online`, real PowerShell 40961/40962/53504 events parsed.
* Resilience test: server killed → agent spooled 1 batch (10 events) → server restarted → `replayed
  10 spooled events`, spool empty, no loss. Found and fixed the Windows file-input identity bug
  (first-256-bytes hash → `st_dev:st_ino`).
* `scripts/gen-certs.sh` fixed for Git Bash (`MSYS_NO_PATHCONV=1`); CA + server + agent certs in `certs/`.
* Sysmon XML validated (schema 4.90, 17 groups); shell/PowerShell scripts syntax-checked (9/9 OK).
* Report: `docs/reports/WEEK1-REPORT.md`.

**Week 2 – parsing, normalisation, enrichment.**
* New parsers: `auditd.py`, `apache_error.py` (nginx + Apache error logs), `windows_dhcp.py`,
  fail2ban sub-parser; content sniffing for them; sniff window 16 → 48 bytes (bug found by test).
* `kharibulbul.time.hour/weekday/business_hours` (config `pipeline.timezone_offset_hours: 4`, `business_hours: [8, 19]`).
* Samples: `audit.log`, `nginx-error.log`, `apache-error.log`, `DhcpSrvLog-Sat.log`, `fail2ban.log`; 7 new tests.
* Coverage over samples: 100 % of real log rows hit a specific parser (93.8 % of lines incl. DHCP header text); 89.5 % without any dataset hint.
* Report: `docs/reports/WEEK2-REPORT.md`.

**Week 3 – rules, safe validation, alerting.**
* 18 team rules in `rules/team/{windows,network,linux,web}.yml` (out-of-hours logon on critical assets,
  account on many hosts, RDP → service, download → execute, Defender exclusion, outbound block burst,
  DNS beacon, fail2ban bans (incl. internal), DHCP conflict/denied/out-of-hours, sudo by non-admin,
  sensitive credential files, auditd auth bursts, audit subsystem disabled, 5xx spike, error-log probes, upstream failures) → 95 rules.
* 11 Week-3 scenarios + a 25-scenario coverage pack (`simulate/coverage_pack.py`) → 52 scenarios; every rule but KB-KB-002 exercised.
* New CLI `kharibulbul rules coverage [--out file]` → scenario→rules matrix + never-fired list + baseline noise check (`docs/reports/WEEK3-VALIDATION.md`).
* Webhook verified with a local receiver: 7 alerts, 5 delivered (min_severity high), 0 failures.
* Tabletop via CLI: 13 alerts, ack/investigate/close/false-positive with assignees and notes; history timestamps recorded (`docs/reports/WEEK3-TABLETOP.md`, `docs/INCIDENTS.md`).
* Parser fix: `su` PAM failures; tuning entries in `docs/TUNING-LOG.md`.

**Week 4 – dashboards, playbooks, ops, hardening.**
* Dashboard panels: auth success vs failure (multi-line chart), open alerts by ATT&CK tactic (`alert_tactics()`), events by asset criticality.
* Query language: `field:(a OR b OR c)` / `field:(a AND b)`.
* Playbooks: triage blocks tagged ```` ```kql ````; `tests/test_playbooks.py` compiles every query and checks cited rule ids; every rule now has a playbook (7 gaps fixed).
* TLS/mTLS live test (`config/server-tls-test.yml` + `config/agent-tls-test.yml`): `tls=True`, client cert accepted, wrong shared secret rejected on both sides; TLS paths resolved server-side.
* Reports: `WEEK4-REPORT.md`, `FINAL-REPORT.md`; `CLAUDE.md` rewritten as the repository guide.

**Verification at the end of the session.** pytest 98/98 passed; rules validate 95/95; coverage
94/95, baseline 0 alerts; live runs as listed above. Background test processes stopped.

### 2026-09-27 — Session 1: full build from scratch

**Context.** Assignment B.5 "Local Mini-SIEM (Wazuh + OpenSearch)". The professor rejected a
standard Wazuh installation and asked for an own SIEM with a national Azerbaijani identity:
name **Kharibulbul**, logo = Khari Bulbul flower. Wazuh/OpenSearch/Beats/Sysmon are reference
designs only. Testing must stay defensive: synthetic benign log samples that resemble suspicious
patterns, inside an isolated lab.

**What was built (all new code).**
* `kharibulbul/common/` – KES schema (`schema.py`: ECS-style field dictionary, `finalize()`), YAML
  config with `${ENV}` expansion and defaults, timestamp parsing (ISO with 7-digit Windows fractions,
  RFC3164, CLF, epoch), utilities (flatten/unflatten, IP helpers, glob→regex).
* `kharibulbul/agent/` – Bülbül agent: `file` (rotation/truncation safe), `winlog` (wevtutil polling
  with per-channel bookmarks, exclusions), `journald`, `command` inputs; shipper with
  hello/batch/ack/heartbeat protocol, TLS/mTLS option, exponential back-off, disk spool with size cap
  and ordered replay; stable agent id.
* `kharibulbul/server/` – asyncio server: TCP agent listener (+TLS, shared secret), syslog UDP/TCP,
  FastAPI API (events/alerts/agents/rules/playbooks/dashboard/ingest), static UI, retention loop,
  agent-silence monitor emitting internal events.
* `kharibulbul/pipeline/` – parser registry (windows XML + Sysmon mapper, syslog RFC3164/5424 with
  sshd/sudo/su/useradd/UFW/cron/systemd/logind sub-parsers, nginx/Apache, journald/ECS JSON,
  Windows Firewall log, generic), normaliser, enrichers (direction, GeoIP CSV+MaxMind, assets,
  threat intel with hot reload, severity boost).
* `kharibulbul/store/` – SQLite+FTS5 store (events/alerts/agents/rule_stats, writer thread, WAL),
  query language compiler (KQL-ish → SQL), optional OpenSearch bulk mirror with index template.
* `kharibulbul/detect/` – rule loader/validator, Sigma-like matchers (12 modifiers), condition
  parser (`1 of sel_*` etc.), streaming engine with thresholds (count/distinct per group, event-time
  sliding windows), sequences, suppression, GC, live enable/disable/reload.
* `kharibulbul/alerts/` – alert manager (dedupe on open alert per rule+entity, status workflow,
  history, sample events) and notifier thread (console, JSONL file, webhook, SMTP with min severity).
* `kharibulbul/web/static/` – dashboard SPA (Overview, Events, Alerts, Agents, Rules, Playbooks) with
  own SVG charts, flag palette, Kharibulbul flower logo (`logo.svg`).
* `kharibulbul/simulate/` – 16 safe scenarios generating Windows XML / Sysmon / syslog / nginx
  records; timeline aligned to end at "now".
* `kharibulbul/cli.py` – server, agent, rules validate/list/test, simulate, replay, parse, query,
  alerts (+ack/investigate/close/fp), stats, version.
* Content: 77 rules (`rules/`), 9 playbooks (`playbooks/`), Sysmon config, audit-policy script,
  install scripts (Linux/Windows), certs script, systemd units, scheduled-task registration, rsyslog
  forwarding, lab configs, intel lists, GeoIP zone CSV, samples, index template, weekly plans,
  team roles, presentation outline, complete guide (`GUIDE.md`).

**Key decisions.**
* Flat ECS-style documents (dotted keys) everywhere; `event.code` always a string; lower-case
  process/host names; Sysmon → `event.dataset: windows.sysmon` with `event.module: windows` so
  rules can pre-filter on `module: windows` for both Security 4688 and Sysmon 1.
* SQLite+FTS5 as the primary store (single process, no external services, lab volumes);
  OpenSearch only as an optional mirror to satisfy the "OpenSearch" reference in the assignment.
* Thresholds/sequences use *event time* so replays and delayed agents behave like live traffic.
* Match rules support top-level `group_by` (shorthand for per-entity alerting with suppression).
* GeoIP: own CSV of lab zones first, MaxMind second – works fully offline.
* Validation strictly via synthetic log records + hand-written samples; no attack tooling.
* One playbook draft (lateral movement) was withheld by a content safety filter during writing; it
  was removed and rules KB-WIN-004, KB-LNX-003, KB-COR-004 now point to PB-001/PB-002.

**Verification performed.**
* `pytest`: 52 passed (parsers, query/store, rules/engine semantics, end-to-end scenarios incl.
  baseline-is-quiet, API flow with TestClient).
* `kharibulbul rules validate rules`: 0 problems.
* Live: server started on this PC, `simulate all` → 246 events stored, 48 alerts (7 critical,
  28 high, 8 medium, 5 low), `detect.errors = {}`, overview bundle populated, alert entities
  labelled `host.name=…, source.ip=…`; console and file notifications delivered; server stopped.

**Bugs found and fixed during the session.** YAML descriptions containing `: ` (quoted);
Sysmon module name vs. rule pre-filter; simulator produced too few distinct invalid SSH users and
a single sudo failure line (scenarios adjusted to realistic PAM lines); simulator events stamped
in the future (timeline alignment added); alert entity label used only the last key segment;
missing `__main__.py` for `python -m kharibulbul`; test used a line that legitimately parses as
syslog.

**Environment.** Python 3.12.10 installed via winget on this PC (PATH `python` was the Store stub);
`pip install pyyaml fastapi uvicorn maxminddb pytest httpx`; package installed with `pip install -e .`.
