# Kharibulbul Event Schema (KES)

Every event is a **flat JSON object with dotted keys** that follow the Elastic Common
Schema (ECS) naming, plus a `kharibulbul.*` namespace for our own metadata. Using ECS
names means rules, dashboards, OpenSearch and any future tooling all speak the same
language; the flat layout keeps the rule engine and the store trivially simple.

The authoritative list is `kharibulbul/common/schema.py` (`FIELDS`), also served at
`GET /api/schema`. This page explains the important groups.

## ECS conformance

`kharibulbul/common/ecs.py` enforces the schema on every event (ECS **8.11.0**, written to `ecs.version`):

| Step | Where | What |
|------|-------|------|
| `conform()` | normaliser | lower-cases `event.kind/category/type/outcome` and maps common variants onto the ECS allowed values (`auth` → `authentication`, `create` → `creation`, `failed` → `failure` …); fills `related.hosts`, `related.hash` |
| `validate()` | after enrichment | `@timestamp` is UTC ISO-8601; categorisation fields hold ECS allowed values; `source.ip`/`destination.ip` are IPs; ports, pids, status codes, `event.severity` are integers; `tags`/`related.*` are lists; `geo.country_iso_code` is ISO 3166-1 alpha-2; `geo.location` is `{lat, lon}`; every key is in an ECS field set or a documented extension |
| `to_nested()` | API / export / OpenSearch | flat → nested ECS object, `event.category` and `event.type` as arrays |

A document that fails validation is still stored, tagged `ecs-nonconformant`, and lists the reasons in
`kharibulbul.ecs.problems` (query: `tags:ecs-nonconformant`). Allowed values are served by
`GET /api/schema` (`ecs`). Documented extensions (not ECS field sets): `kharibulbul.*`, `winlog.*`,
`sysmon.*`, `powershell.*`, `auditd.*`, `dhcp.*`, `fail2ban.*`, `cron.*`, `systemd.*`, `journald.*`,
`syslog.*`, `nginx.*`, `apache.*`, `json.*`; free-form labels go under ECS `labels.*`
(the simulator marks its events with `labels.simulation`).

Flat storage vs. ECS shape — the same event:

```json
{"@timestamp": "2026-09-30T15:46:48.865Z", "ecs.version": "8.11.0", "event.category": "authentication",
 "event.outcome": "failure", "source.ip": "77.88.8.8", "source.geo.country_iso_code": "RU"}
```
```json
{"@timestamp": "2026-09-30T15:46:48.865Z", "ecs": {"version": "8.11.0"},
 "event": {"category": ["authentication"], "outcome": "failure"},
 "source": {"ip": "77.88.8.8", "geo": {"country_iso_code": "RU"}}}
```
The second form is what `GET /api/events?format=ecs`, *export ECS JSON*, `kharibulbul parse --ecs` and
the OpenSearch mirror produce.

## Mandatory fields (set by `finalize()`)

| Field | Example | Notes |
|-------|---------|-------|
| `@timestamp` | `2026-09-27T10:00:00.123Z` | event time, UTC ISO-8601 (ms) |
| `ecs.version` | `8.11.0` | ECS version the event is normalised to |
| `event.id` | `9f1c…` | unique id (uuid4 hex) |
| `event.kind` | `event` | `alert` for alert documents |
| `event.dataset` | `windows.security`, `linux.auth`, `nginx.access` | logical source |
| `event.module` | `windows`, `linux`, `web`, `json` | dataset prefix |
| `event.outcome` | `success` / `failure` / `unknown` | |
| `event.severity` | `10` … `100` | informational 10, low 30, medium 50, high 75, critical 95 |
| `event.ingested` | ISO time | when the server processed it |
| `message` | text | human summary produced by the parser |
| `tags` | `["invalid-user"]` | list, may be empty |

## Event classification

| Field | Values used by our parsers |
|-------|---------------------------|
| `event.category` | `authentication`, `process`, `network`, `file`, `registry`, `iam`, `configuration`, `session`, `web`, `malware`, `driver`, `host` |
| `event.type` | `start`, `end`, `creation`, `deletion`, `change`, `access`, `connection`, `allowed`, `denied`, `info`, `user`, `group`, `admin` |
| `event.action` | normalised verb, e.g. `logon-failed`, `logon-success`, `process-created`, `network-connection`, `dns-query`, `ssh-login-failed`, `sudo-command`, `user-created`, `group-member-added`, `service-installed`, `scheduled-task-created`, `audit-log-cleared`, `firewall-block`, `http-request` |
| `event.code` | provider code as string: Windows EventID (`4625`), Sysmon id (`1`) |
| `event.provider` | `Microsoft-Windows-Security-Auditing`, `Microsoft-Windows-Sysmon`, `sshd` … |

Rules should prefer `event.action` (stable across sources) and fall back to `event.code`
for provider-specific detail.

## Host / agent

`host.name` (lower-case short name), `host.ip` (list), `host.os.type` (`windows`/`linux`),
`host.role` (from `config/assets.yml`), `agent.id`, `agent.name`, `agent.version`,
`agent.type` (`kharibulbul-agent`, `syslog-udp`, `http`, `simulate`, `replay`, `internal`).

## Users

`user.name` / `user.domain` / `user.id` = the acting subject; `user.target.name` = the account
being acted on (logon target, created user, group member); `user.effective.name` = sudo/su target.
`related.user` collects all of them for searching.

## Network

`source.ip`, `source.port`, `source.domain`, `destination.ip`, `destination.port`,
`destination.domain`, `network.transport` (`tcp`/`udp`), `network.protocol` (`ssh`, `dns`, `http`),
`network.type` (`ipv4`/`ipv6`), `network.direction` (`inbound`/`outbound`/`internal`/`external`),
`kharibulbul.network.zone_direction` (same idea computed purely from `pipeline.lab_networks`),
`related.ip` (all IPs in the event), `related.hosts`, `related.hash`.

GeoIP adds `source.geo.name` (lab zone or country), `source.geo.country_iso_code` (ISO 3166-1
alpha-2; `XL` = lab private range, `XX` = documentation range), `source.geo.country_name`,
`source.geo.continent_code` / `continent_name`, `source.geo.city_name`, `source.geo.location`
(`{lat, lon}`), `source.as.organization.name` – and the same for `destination.*`. Every public
address gets at least country and continent (see `geoip/README.md`).

## Process (Sysmon 1 / 4688 / sudo / cron)

`process.pid`, `process.name` (lower-case image name), `process.executable`, `process.command_line`,
`process.args` (list), `process.entity_id` (Sysmon GUID), `process.hash.sha256|md5|sha1|imphash`,
`process.pe.original_file_name|company|description|product`, `process.integrity_level`,
`process.working_directory`, `process.parent.pid|name|executable|command_line|entity_id`,
`process.target.name|pid` (Sysmon 8/10 target).

## File / registry / DNS / web / service

* `file.path`, `file.name`, `file.extension`, `file.directory`, `file.hash.sha256`, `file.code_signature.*`
* `registry.path`, `registry.hive`, `registry.value`, `registry.data.strings`, `sysmon.event_type`
* `dns.question.name`, `dns.question.registered_domain`, `dns.question.top_level_domain`, `dns.answers.data`
* `url.original`, `url.path`, `url.query`, `http.request.method`, `http.response.status_code`, `http.response.body.bytes`, `user_agent.original`, `http.request.referrer`
* `service.name`, `service.path`, `service.type`, `service.start_type`, `service.account`, `service.state`
* `group.name`, `group.domain`

## Windows-specific

`winlog.channel`, `winlog.provider_name`, `winlog.record_id`, `winlog.computer_name`,
`winlog.event_data.<Name>` (every `<Data Name=…>` value, untouched), `winlog.logon.type`
(`interactive`, `network`, `remote-interactive` …), `winlog.logon.id`,
`winlog.logon.failure.status` / `.reason`, `winlog.task.name` / `.content`, `winlog.privileges`,
`powershell.file.script_block_text`, `sysmon.granted_access`, `sysmon.call_trace`, `sysmon.rule_name`.

## Linux-specific

`log.syslog.facility.name`, `log.syslog.severity.name`, `log.syslog.appname`, `log.syslog.hostname`,
`kharibulbul.auth.method` (`password`/`publickey`), `observer.ingress.interface.name` (firewall).

## Enrichment / SIEM metadata

* `kharibulbul.asset.criticality`, `kharibulbul.asset.owner`, `labels.*`
* `threat.indicator.matched`, `threat.indicator.type` (`ipv4-addr`/`domain-name`/`file-hash`), `threat.indicator.value`, `threat.indicator.description`
* `kharibulbul.pipeline.parser` (which parser produced the doc), `kharibulbul.pipeline.errors`
* `event.original` – the raw line/XML (kept for forensics; capped at 32 kB)

## Alert documents

Alerts are separate objects (`GET /api/alerts`): `id`, `rule.id`, `rule.name`, `rule.description`,
`severity`, `severity_score`, `status` (`new`, `acknowledged`, `investigating`, `escalated`, `closed`,
`false_positive`), `entity`, `group_key`, `group_values`, `first_seen`, `last_seen`, `count`,
`host.name`, `user.name`, `source.ip`, `mitre` (list of `{technique, tactic}`), `tags`, `playbook`,
`sample_events` (trimmed copies of up to 10 triggering events), `assignee`, `notes`, `history`,
`escalation` (`{level 1-3, to, reason, by, ts, severity_before, severity_after}` once escalated).

## Design decisions

* **Flat keys** – `doc["source.ip"]` everywhere; `ecs.to_nested()` builds the nested ECS object on demand.
* **Scalars for categorisation** – `event.category` / `event.type` hold one value in the flat store (rules
  and SQL columns compare strings); the nested ECS view turns them into the arrays ECS defines.
* **Strings for codes** – `event.code` is always a string so `4625` and `"4625"` compare equally in rules.
* **Lower-case names** – `process.name`, `host.name` are lower-cased; rule matching is case-insensitive anyway.
* **Never lose data** – unknown fields are kept; parser problems are tagged, not dropped.
