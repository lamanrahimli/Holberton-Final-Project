# Dashboards

## Built-in (primary deliverable)

The Kharibulbul web UI (`kharibulbul/web/static/`, served at `http://server:8080/ui/`) is written
from scratch in vanilla JavaScript with our own SVG chart renderers – no build step, no CDN, works in
the isolated lab.

| Page | Panels | Backing API |
|------|--------|-------------|
| **Overview** | events in range · open alerts (critical/high) · authentication failures · agents online · store size · events over time · alerts over time · alerts by severity (donut) · top hosts / actions / source IPs / datasets / users / countries (GeoIP) / processes · recent alerts · alerts by rule | `GET /api/dashboard/overview?from=now-24h` |
| **Events** | query box (Kharibulbul query language), time range, histogram, results table, side panel with clickable datasets/actions/hosts, event drawer (fields + raw), JSON export | `/api/events`, `/histogram`, `/terms` |
| **Alerts** | filters (status, severity, text, range), by-severity donut, by-status, by-rule, alert table, drawer with triage actions (acknowledge / investigate / close / false positive, assignee, notes), sample events, MITRE links, playbook link | `/api/alerts`, `PATCH /api/alerts/{id}` |
| **Agents** | status (online / silent / disconnected), host, IPs, OS, version, events, last seen | `/api/agents` |
| **Rules** | enable/disable toggles, kind, severity, MITRE, hits, alerts, last hit, YAML view, reload from disk | `/api/rules` |
| **Playbooks** | markdown rendering of `playbooks/` | `/api/playbooks` |

Auto-refresh: Overview every 30 s. Time ranges: 15 m … 30 d. Colours: Azerbaijani flag blue
`#0092BC`, red `#E4002B`, green `#00AF66` on a dark SOC theme.

### Adding a panel (Week 4 exercise)
1. Add an aggregation to `SQLiteStore` (or reuse `terms()` / `histogram()`).
2. Return it from `overview()` in `kharibulbul/server/api.py`.
3. Render it in `renderOverview()` in `app.js` with `hbars()`, `barChart()`, `areaChart()` or `donut()`.

## OpenSearch Dashboards (optional mirror)

The assignment lists OpenSearch as a tool; Kharibulbul can mirror every document into OpenSearch
(`store.opensearch.enabled: true` in `config/server.yml`) using the ECS-style field names, so
OpenSearch Dashboards can be used on the same data for the demo.

1. Run OpenSearch + OpenSearch Dashboards (single node, e.g. the official docker-compose) on a VM with
   enough RAM (≥4 GB).
2. Put `opensearch/index-template.json` in place:
   `curl -k -u admin:<pw> -X PUT https://os:9200/_index_template/kharibulbul -H 'Content-Type: application/json' -d @dashboards/opensearch/index-template.json`
   (the server also installs the same template automatically at start).
3. Enable the mirror and restart the server; indices `kharibulbul-events-YYYY.MM.dd` appear.
4. In OpenSearch Dashboards create the index pattern `kharibulbul-events-*` (time field `@timestamp`)
   and build visualisations: events per `host.name`, `event.action` pie, `source.geo.location` map
   (needs MaxMind data for public IPs), authentication failures timeline.
5. Export the dashboard (Stack Management → Saved objects → Export) and commit the `.ndjson` here.

Note: the primary store stays SQLite; OpenSearch is write-only from Kharibulbul's point of view.
