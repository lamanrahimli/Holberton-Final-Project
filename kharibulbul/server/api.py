"""HTTP API + web UI (FastAPI).

All JSON endpoints live under /api; the single-page dashboard is served from
/ui (static files in kharibulbul/web/static).  If ``api.token`` is set in the
server config, every /api call must send ``Authorization: Bearer <token>``
(or ``X-API-Key``).
"""
from __future__ import annotations

import os
import time
from typing import Any

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .. import __app_name__, __version__
from ..common import ecs
from ..common.schema import FIELDS, SEVERITIES
from ..common.timeutil import from_epoch, now_iso, parse_duration, parse_relative
from ..common.util import local_ips, new_id
from ..detect.rules import build_rule, validate_rule
from ..store.query import QueryError
from . import enroll
from .content import PLAYBOOK_TEMPLATE, ContentError

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "static")

_STEPS = (1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400, 172800, 604800, 1209600, 2592000,
          7776000, 15552000, 31536000)


def _interval_for(since, until, buckets: int = 60) -> float:
    """Bucket width that keeps a chart at about ``buckets`` points, from seconds up to years."""
    span = max(1.0, (until - since).total_seconds())
    raw = span / buckets
    for step in _STEPS:
        if raw <= step:
            return float(step)
    return float(_STEPS[-1] * (int(raw // _STEPS[-1]) + 1))


def ui_build() -> str:
    """Identifies the dashboard files on disk (version + newest modification time)."""
    try:
        newest = max(int(os.path.getmtime(os.path.join(STATIC_DIR, f))) for f in os.listdir(STATIC_DIR))
    except (OSError, ValueError):
        newest = 0
    return f"{__version__}-{newest}"


class _NoCacheStatic(StaticFiles):
    """Static files that the browser has to revalidate on every load."""

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


class _MemoryAlerts:
    """Alert manager stand-in used by /api/rules/test (nothing is stored)."""

    def __init__(self) -> None:
        self.alerts: list[dict] = []

    def raise_alert(self, rule, doc, ts, count, group_fields, group_key, group_values, samples, suppress, extra=None):
        alert = {"rule.id": rule.id, "rule.name": rule.title, "count": count, "group_key": group_key,
                 "group_values": group_values, "trigger_event_id": doc.get("event.id"), "message": doc.get("message")}
        self.alerts.append(alert)
        return alert

    def touch(self, rule, group_key, ts, extra=1):
        return None


def create_app(server) -> FastAPI:
    cfg = server.cfg
    app = FastAPI(title=__app_name__, version=__version__, docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    api = APIRouter(prefix="/api")

    # ------------------------------------------------------------------ #
    def auth(request: Request) -> None:
        token = (cfg.get("api") or {}).get("token") or ""
        if not token:
            return
        header = request.headers.get("authorization", "")
        provided = header[7:] if header.lower().startswith("bearer ") else request.headers.get("x-api-key") or request.query_params.get("api_key")
        if provided != token:
            raise HTTPException(401, "invalid or missing API token")

    if (cfg.get("api") or {}).get("cors"):
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    def _time(value: str | None, default: str | None):
        """'now-24h', an ISO date / date-time, or 'all' (= since the oldest stored event)."""
        if value is None or value == "":
            value = default
        if value is None:
            return None
        if str(value).strip().lower() == "all":
            oldest = server.store.oldest_ts()
            return from_epoch(oldest - 1) if oldest is not None else parse_relative("now-24h")
        try:
            return parse_relative(value)
        except ValueError as exc:
            raise HTTPException(400, f"bad time value {value!r}: {exc}") from None

    def _range(from_: str | None, to: str | None, default_from: str):
        since, until = _time(from_, default_from), _time(to, "now")
        if until <= since:
            raise HTTPException(400, "'to' must be later than 'from'")
        return since, until

    async def _body(request: Request) -> dict:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "request body must be JSON") from None
        if not isinstance(body, dict):
            raise HTTPException(400, "request body must be a JSON object")
        return body

    def _content_error(exc: ContentError) -> HTTPException:
        return HTTPException(exc.status, str(exc))

    # ------------------------------------------------------------------ #
    @api.get("/health")
    def health() -> dict:
        return {"status": "ok", "name": __app_name__, "version": __version__, "time": now_iso(),
                "uptime_seconds": round(time.time() - server.started, 1), "ui": ui_build()}

    @api.get("/stats", dependencies=[Depends(auth)])
    def stats() -> dict:
        geo = getattr(server.pipeline.enricher, "geoip", None)
        return {
            "server": {"version": __version__, "uptime_seconds": round(time.time() - server.started, 1), "time": now_iso(),
                       "retention_days": float(cfg["store"].get("retention_days") or 0)},
            "pipeline": server.pipeline.snapshot(),
            "ingest": server.ingest.snapshot() if server.ingest else {},
            "store": server.store.db_stats(),
            "detect": server.engine.snapshot(),
            "alerts": {"created": server.alert_manager.created, "updated": server.alert_manager.updated,
                       "escalated": server.alert_manager.escalated,
                       "notifications": server.notifier.sent, "notification_failures": server.notifier.failures},
            "geoip": geo.snapshot() if geo else None,
            "opensearch": {"enabled": server.opensearch is not None,
                           "sent": server.opensearch.sent if server.opensearch else 0,
                           "errors": server.opensearch.errors if server.opensearch else 0},
        }

    @api.get("/schema", dependencies=[Depends(auth)])
    def schema() -> dict:
        def is_ecs(name: str) -> bool:
            return name in ecs.ECS_BASE_FIELDS or name.split(".", 1)[0] in ecs.ECS_FIELD_SETS
        return {"fields": {k: {"type": t, "description": d, "ecs": is_ecs(k)} for k, (t, d) in FIELDS.items()},
                "severities": list(SEVERITIES),
                "ecs": {"version": ecs.ECS_VERSION, "event.kind": sorted(ecs.EVENT_KINDS),
                        "event.category": sorted(ecs.EVENT_CATEGORIES), "event.type": sorted(ecs.EVENT_TYPES),
                        "event.outcome": sorted(ecs.EVENT_OUTCOMES), "extensions": sorted(ecs.CUSTOM_FIELD_SETS)}}

    # ------------------------------------------------------------------ #
    # events
    # ------------------------------------------------------------------ #
    @api.get("/events", dependencies=[Depends(auth)])
    def events(q: str = "", from_: str | None = Query(None, alias="from"), to: str | None = None,
               limit: int = Query(100, ge=1, le=5000), offset: int = Query(0, ge=0), sort: str = "desc",
               format: str = "") -> dict:
        since, until = _time(from_, None), _time(to, None)
        try:
            hits = server.store.search(q, since, until, limit, offset, sort)
            total = server.store.count(q, since, until)
        except QueryError as exc:
            raise HTTPException(400, f"query error: {exc}") from None
        if format.lower() == "ecs":
            hits = [ecs.to_nested(h) for h in hits]
        return {"total": total, "hits": hits, "limit": limit, "offset": offset, "query": q}

    @api.get("/events/histogram", dependencies=[Depends(auth)])
    def events_histogram(q: str = "", from_: str | None = Query(None, alias="from"), to: str | None = None,
                         interval: str | None = None) -> dict:
        since, until = _range(from_, to, "now-1h")
        step = parse_duration(interval) if interval else _interval_for(since, until)
        try:
            buckets = server.store.histogram(q, since, until, step)
        except QueryError as exc:
            raise HTTPException(400, f"query error: {exc}") from None
        return {"interval_seconds": step, "buckets": buckets}

    @api.get("/events/terms", dependencies=[Depends(auth)])
    def events_terms(field: str, q: str = "", from_: str | None = Query(None, alias="from"), to: str | None = None,
                     size: int = Query(10, ge=1, le=500)) -> dict:
        since, until = _range(from_, to, "now-24h")
        try:
            return {"field": field, "buckets": server.store.terms(field, q, since, until, size)}
        except QueryError as exc:
            raise HTTPException(400, f"query error: {exc}") from None

    @api.get("/events/{event_id}", dependencies=[Depends(auth)])
    def event(event_id: str, format: str = "") -> dict:
        doc = server.store.get_event(event_id)
        if not doc:
            raise HTTPException(404, "event not found")
        return ecs.to_nested(doc) if format.lower() == "ecs" else doc

    @api.post("/ingest", dependencies=[Depends(auth)])
    async def ingest(request: Request) -> dict:
        if not (cfg.get("ingest") or {}).get("http", {}).get("enabled", True):
            raise HTTPException(403, "HTTP ingest disabled")
        body = await request.json()
        if isinstance(body, dict) and "events" in body:
            envelopes = body["events"]
        elif isinstance(body, list):
            envelopes = body
        elif isinstance(body, dict):
            envelopes = [body]
        else:
            raise HTTPException(400, "send an envelope, a list of envelopes or {\"events\": [...]}")
        if not all(isinstance(e, dict) for e in envelopes):
            raise HTTPException(400, "every envelope must be an object")
        client = request.client.host if request.client else ""
        import asyncio
        n = await asyncio.get_running_loop().run_in_executor(
            None, server.handle_batch, envelopes, {"agent": {"type": "http", "id": body.get("agent_id") if isinstance(body, dict) else None}, "remote": client})
        return {"received": len(envelopes), "stored": n}

    # ------------------------------------------------------------------ #
    # alerts
    # ------------------------------------------------------------------ #
    @api.get("/alerts", dependencies=[Depends(auth)])
    def alerts(status: str | None = None, severity: str | None = None, rule: str | None = None, q: str | None = None,
               from_: str | None = Query(None, alias="from"), to: str | None = None,
               limit: int = Query(100, ge=1, le=2000), offset: int = Query(0, ge=0)) -> dict:
        items = server.store.list_alerts(status=status, severity=severity, rule_id=rule, since=_time(from_, None),
                                         until=_time(to, None), text=q, limit=limit, offset=offset)
        return {"hits": items, "count": len(items)}

    @api.get("/alerts/summary", dependencies=[Depends(auth)])
    def alerts_summary(from_: str | None = Query(None, alias="from")) -> dict:
        return server.store.alert_counts(since=_time(from_, None))

    @api.get("/alerts/histogram", dependencies=[Depends(auth)])
    def alerts_histogram(from_: str | None = Query(None, alias="from"), to: str | None = None, interval: str | None = None) -> dict:
        since, until = _range(from_, to, "now-24h")
        step = parse_duration(interval) if interval else _interval_for(since, until, 48)
        return {"interval_seconds": step, "buckets": server.store.alerts_histogram(since, until, step)}

    @api.get("/alerts/{alert_id}", dependencies=[Depends(auth)])
    def alert(alert_id: str) -> dict:
        doc = server.store.get_alert(alert_id)
        if not doc:
            raise HTTPException(404, "alert not found")
        return doc

    def _escalate(alert_id: str, body: dict) -> dict:
        try:
            doc = server.alert_manager.escalate(
                alert_id, to=body.get("to"), reason=body.get("reason"), by=body.get("by") or body.get("assignee"),
                raise_severity=bool(body.get("raise_severity", True)), assignee=body.get("assignee"), notes=body.get("notes"))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if not doc:
            raise HTTPException(404, "alert not found")
        return doc

    @api.patch("/alerts/{alert_id}", dependencies=[Depends(auth)])
    async def update_alert(alert_id: str, request: Request) -> dict:
        body = await _body(request)
        if body.get("status") == "escalated":
            return _escalate(alert_id, body)
        try:
            doc = server.alert_manager.update(alert_id, status=body.get("status"), assignee=body.get("assignee"), notes=body.get("notes"))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if not doc:
            raise HTTPException(404, "alert not found")
        return doc

    @api.post("/alerts/{alert_id}/escalate", dependencies=[Depends(auth)])
    async def escalate_alert(alert_id: str, request: Request) -> dict:
        """Hand the alert to the next tier: body ``{to, reason, by, raise_severity, assignee, notes}`` (all optional)."""
        return _escalate(alert_id, await _body(request))

    # ------------------------------------------------------------------ #
    # agents
    # ------------------------------------------------------------------ #
    def _agent_view(a: dict) -> dict:
        ips = [ip for ip in (a.get("ip") or []) if ip]
        routable = [ip for ip in ips if not ip.lower().startswith("fe80:") and not ip.startswith("169.254.")]
        a["ip_primary"] = (routable or ips or [a.get("remote") or ""])[0] or None
        return a

    @api.get("/agents", dependencies=[Depends(auth)])
    def agents() -> dict:
        timeout = parse_duration((cfg.get("agents") or {}).get("heartbeat_timeout", "5m"))
        return {"agents": [_agent_view(a) for a in server.store.list_agents(timeout)]}

    def _enroll_defaults() -> dict:
        tcp = (cfg.get("ingest") or {}).get("tcp") or {}
        addresses = [ip for ip in local_ips() if not ip.lower().startswith("fe80:") and not ip.startswith("169.254.")]
        return {"server_addresses": addresses, "server_host": addresses[0] if addresses else "127.0.0.1",
                "port": int(tcp.get("port", 5044)), "tls": bool((tcp.get("tls") or {}).get("enabled")),
                "secret_required": bool((cfg.get("ingest") or {}).get("shared_secret")),
                "profiles": enroll.PROFILES, "version": __version__}

    @api.get("/agents/enroll/info", dependencies=[Depends(auth)])
    def agents_enroll_info() -> dict:
        """What the "Add agent" wizard needs to pre-fill: this server's addresses, ingest port, TLS, profiles."""
        return _enroll_defaults()

    @api.post("/agents/enroll", dependencies=[Depends(auth)])
    async def agents_enroll(request: Request) -> dict:
        """Register a new agent as *pending* and return its configuration file and install guide."""
        body = await _body(request)
        try:
            params = enroll.clean_params(body, _enroll_defaults())
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if any((a.get("name") or "").lower() == params["name"].lower() for a in server.store.list_agents(float("inf"))):
            raise HTTPException(409, f"an agent named {params['name']} already exists - choose another name or remove the old one")
        agent_id = new_id()
        labels = {k: v for k, v in (("zone", params["zone"]), ("os", params["os"]), ("enrolled", "dashboard")) if v}
        server.store.upsert_agent({"id": agent_id, "name": params["name"], "host": "", "ip": [], "os": params["os"],
                                   "version": "", "labels": labels, "status": "pending", "remote": ""})
        return {"agent": _agent_view(server.store.get_agent(agent_id) or {"id": agent_id}), "filename": f"agent-{params['name']}.yml",
                "config": enroll.build_config(params, agent_id), "steps": enroll.install_steps(params), "params": params}

    @api.delete("/agents/{agent_id}", dependencies=[Depends(auth)])
    def agent_delete(agent_id: str) -> dict:
        """Forget an agent (its stored events stay). A running agent simply registers again on its next hello."""
        if not server.store.delete_agent(agent_id):
            raise HTTPException(404, "agent not found")
        return {"id": agent_id, "deleted": True}

    # ------------------------------------------------------------------ #
    # rules
    # ------------------------------------------------------------------ #
    @api.get("/rules", dependencies=[Depends(auth)])
    def rules() -> dict:
        stats = server.store.rule_stats()
        live = server.engine.snapshot()["hits"]
        out = []
        for r in server.engine.all_rules():
            d = r.to_public()
            d["stats"] = stats.get(r.id, {"hits": 0, "alerts": 0, "last_hit": None})
            d["stats"]["hits_this_session"] = live.get(r.id, 0)
            out.append(d)
        out.sort(key=lambda d: d["id"])
        return {"rules": out, "count": len(out), "custom": sum(1 for d in out if d["custom"])}

    @api.get("/rules/template", dependencies=[Depends(auth)])
    def rule_template() -> dict:
        """A commented starting point for a custom rule with the next free KB-CUS id."""
        existing = server.engine.all_rules()
        return {"id": server.content.next_rule_id(existing), "yaml": server.content.rule_template(existing)}

    @api.post("/rules", dependencies=[Depends(auth)])
    async def rule_create(request: Request) -> dict:
        """Create a custom rule from YAML text (``{"rule": "<yaml>"}``); it is validated, saved and loaded at once."""
        body = await _body(request)
        try:
            rule_obj = server.content.save_rule(body.get("rule") or body.get("yaml") or "", server.engine.all_rules())
        except ContentError as exc:
            raise _content_error(exc) from None
        loaded = server.reload_rules()
        return {"rule": rule_obj.to_public(), "loaded": loaded}

    @api.get("/rules/{rule_id}", dependencies=[Depends(auth)])
    def rule(rule_id: str) -> dict:
        for r in server.engine.all_rules():
            if r.id == rule_id:
                d = r.to_public()
                if r.path and os.path.exists(r.path):
                    with open(r.path, "r", encoding="utf-8") as fh:
                        text = fh.read()
                    if r.custom:
                        d["yaml"] = text
                    else:       # a shipped file holds several rules: show only this one
                        docs = [part for part in text.split("\n---") if part.strip()]
                        mine = [part for part in docs if any(line.strip() == f"id: {r.id}" for line in part.splitlines())]
                        d["yaml"] = (mine[0].strip("\n") + "\n") if mine else text
                return d
        raise HTTPException(404, "rule not found")

    @api.put("/rules/{rule_id}", dependencies=[Depends(auth)])
    async def rule_update(rule_id: str, request: Request) -> dict:
        body = await _body(request)
        try:
            rule_obj = server.content.save_rule(body.get("rule") or body.get("yaml") or "", server.engine.all_rules(), rule_id)
        except ContentError as exc:
            raise _content_error(exc) from None
        loaded = server.reload_rules()
        return {"rule": rule_obj.to_public(), "loaded": loaded}

    @api.delete("/rules/{rule_id}", dependencies=[Depends(auth)])
    def rule_delete(rule_id: str) -> dict:
        try:
            server.content.delete_rule(rule_id, server.engine.all_rules())
        except ContentError as exc:
            raise _content_error(exc) from None
        return {"id": rule_id, "deleted": True, "loaded": server.reload_rules()}

    @api.post("/rules/{rule_id}/enable", dependencies=[Depends(auth)])
    def rule_enable(rule_id: str) -> dict:
        if not server.engine.set_enabled(rule_id, True):
            raise HTTPException(404, "rule not found")
        return {"id": rule_id, "enabled": True}

    @api.post("/rules/{rule_id}/disable", dependencies=[Depends(auth)])
    def rule_disable(rule_id: str) -> dict:
        if not server.engine.set_enabled(rule_id, False):
            raise HTTPException(404, "rule not found")
        return {"id": rule_id, "enabled": False}

    @api.post("/rules/reload", dependencies=[Depends(auth)])
    def rules_reload() -> dict:
        n = server.reload_rules()
        return {"loaded": n}

    @api.post("/rules/test", dependencies=[Depends(auth)])
    async def rules_test(request: Request) -> dict:
        """Dry-run a rule (YAML text) against sample events (list of flat docs or raw lines)."""
        body = await request.json()
        text = body.get("rule")
        if not text:
            raise HTTPException(400, "'rule' (yaml text) required")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise HTTPException(400, f"yaml error: {exc}") from None
        errors = validate_rule(data)
        if errors:
            return {"valid": False, "errors": errors}
        rule_obj = build_rule(data, "<test>")
        from ..detect.engine import DetectionEngine
        mem = _MemoryAlerts()
        engine = DetectionEngine([rule_obj], mem, default_suppress=0)
        matches = []
        for item in body.get("events") or []:
            doc = server.pipeline.process(item if isinstance(item, dict) and "raw" in item else
                                          ({"raw": item} if isinstance(item, str) else {"raw": __import__("json").dumps(item)}))
            if doc is None:
                continue
            matched = rule_obj.prefilter(doc) and rule_obj.matches(doc) if not rule_obj.sequence else None
            engine.evaluate(doc)
            matches.append({"event.id": doc.get("event.id"), "message": doc.get("message"), "matched": matched,
                            "event.dataset": doc.get("event.dataset"), "event.action": doc.get("event.action")})
        return {"valid": True, "rule": rule_obj.to_public(), "events": matches, "alerts": mem.alerts}

    # ------------------------------------------------------------------ #
    # playbooks
    # ------------------------------------------------------------------ #
    @api.get("/playbooks", dependencies=[Depends(auth)])
    def playbooks() -> dict:
        items = server.content.list_playbooks()
        return {"playbooks": [i["name"] for i in items], "items": items, "template": PLAYBOOK_TEMPLATE}

    @api.post("/playbooks", dependencies=[Depends(auth)])
    async def playbook_create(request: Request) -> dict:
        """Create a custom playbook: ``{"name": "PB-C01-phishing.md", "content": "<markdown>"}``."""
        body = await _body(request)
        try:
            return server.content.save_playbook(body.get("name") or "", body.get("content") or "", create=True)
        except ContentError as exc:
            raise _content_error(exc) from None

    @api.get("/playbooks/{name}", dependencies=[Depends(auth)])
    def playbook(name: str) -> PlainTextResponse:
        found = server.content.read_playbook(name)
        if found is None:
            raise HTTPException(404, "playbook not found")
        return PlainTextResponse(found[0], media_type="text/markdown", headers={"X-Kharibulbul-Custom": "1" if found[1] else "0"})

    @api.put("/playbooks/{name}", dependencies=[Depends(auth)])
    async def playbook_update(name: str, request: Request) -> dict:
        body = await _body(request)
        try:
            return server.content.save_playbook(name, body.get("content") or "", create=False)
        except ContentError as exc:
            raise _content_error(exc) from None

    @api.delete("/playbooks/{name}", dependencies=[Depends(auth)])
    def playbook_delete(name: str) -> dict:
        try:
            server.content.delete_playbook(name)
        except ContentError as exc:
            raise _content_error(exc) from None
        return {"name": name, "deleted": True}

    # ------------------------------------------------------------------ #
    # GeoIP
    # ------------------------------------------------------------------ #
    @api.get("/geoip/lookup", dependencies=[Depends(auth)])
    def geoip_lookup(ip: str) -> dict:
        """What the enrichment stage would add for this address (custom ranges -> MaxMind -> country table)."""
        geo = getattr(server.pipeline.enricher, "geoip", None)
        info = geo.lookup(ip) if geo else None
        if info is None:
            raise HTTPException(400, f"{ip!r} is not an IP address")
        return {"ip": ip, "geo": info}

    # ------------------------------------------------------------------ #
    # dashboard bundle
    # ------------------------------------------------------------------ #
    @api.get("/dashboard/overview", dependencies=[Depends(auth)])
    def overview(from_: str | None = Query("now-24h", alias="from"), to: str | None = None, q: str = "") -> dict:
        since, until = _range(from_, to, "now-24h")
        store = server.store
        step = _interval_for(since, until, 48)
        timeout = parse_duration((cfg.get("agents") or {}).get("heartbeat_timeout", "5m"))
        agents = store.list_agents(timeout)
        try:
            data: dict[str, Any] = {
                "range": {"from": since.isoformat(), "to": until.isoformat(), "interval_seconds": step},
                "events_total": store.count(q, since, until),
                "events_histogram": store.histogram(q, since, until, step),
                "alerts_histogram": store.alerts_histogram(since, until, step),
                "alerts": store.alert_counts(since=since),
                "recent_alerts": store.list_alerts(since=since, limit=10),
                "top_hosts": store.terms("host.name", q, since, until, 8),
                "top_datasets": store.terms("event.dataset", q, since, until, 8),
                "top_actions": store.terms("event.action", q, since, until, 10),
                "top_users": store.terms("user.name", q, since, until, 8),
                "top_source_ips": store.terms("source.ip", q, since, until, 8),
                "top_countries": store.terms("source.geo.country_name", q, since, until, 8),
                "top_dest_countries": store.terms("destination.geo.country_name", q, since, until, 8),
                "top_processes": store.terms("process.name", q, since, until, 8),
                "auth_failures": store.count("event.category:authentication AND event.outcome:failure" + (f" AND ({q})" if q else ""), since, until),
                "agents": {"total": len(agents), "online": sum(1 for a in agents if a["status"] == "online"),
                           "silent": sum(1 for a in agents if a["status"] in ("silent", "disconnected")),
                           "pending": sum(1 for a in agents if a["status"] == "pending")},
                "store": store.db_stats(),
                # Week 4 panels: ATT&CK tactics of open alerts, auth success vs failure, asset criticality
                "alert_tactics": store.alert_tactics(since=since),
                "auth_histogram": {
                    "success": store.histogram("event.category:authentication AND event.outcome:success" + (f" AND ({q})" if q else ""), since, until, step),
                    "failure": store.histogram("event.category:authentication AND event.outcome:failure" + (f" AND ({q})" if q else ""), since, until, step),
                },
                "criticality": store.terms("kharibulbul.asset.criticality", q, since, until, 5),
            }
        except QueryError as exc:
            raise HTTPException(400, f"query error: {exc}") from None
        return data

    app.include_router(api)

    # ------------------------------------------------------------------ #
    # web UI
    # ------------------------------------------------------------------ #
    # A browser must never run an old dashboard against a new server: without Cache-Control it keeps a
    # script for hours (heuristic freshness). So every static response says "no-cache" (revalidate, 304 is
    # cheap) and the page links its assets with ?v=<build>, which changes whenever a file changes.
    def _page() -> HTMLResponse:
        with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as fh:
            html = fh.read()
        build = ui_build()
        for name in ("style.css", "app.js", "favicon.png", "logo.png"):
            html = html.replace(f'"{name}"', f'"{name}?v={build}"')
        return HTMLResponse(html, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(f"/ui/?v={ui_build()}", headers={"Cache-Control": "no-store"})

    @app.get("/logo.png", include_in_schema=False)
    def logo():
        return FileResponse(os.path.join(STATIC_DIR, "logo.png"), media_type="image/png", headers={"Cache-Control": "no-cache"})

    if os.path.isdir(STATIC_DIR):
        app.get("/ui/", include_in_schema=False)(_page)
        app.get("/ui/index.html", include_in_schema=False)(_page)
        app.mount("/ui", _NoCacheStatic(directory=STATIC_DIR, html=True), name="ui")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # pragma: no cover
        return JSONResponse(status_code=500, content={"error": str(exc)})

    return app
