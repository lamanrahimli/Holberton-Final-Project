"""Kharibulbul command line: server, agent, rules, simulate, replay, parse, query, alerts, stats."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

from . import __app_name__, __version__
from .common.util import chunked, json_dumps, project_root


def _api(server: str, path: str, token: str | None = None, method: str = "GET", body=None, params: dict | None = None):
    url = server.rstrip("/") + path
    if params:
        url += "?" + urlencode({k: v for k, v in params.items() if v not in (None, "")})
    data = json_dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        sys.exit(f"API error {exc.code} for {path}: {detail}")
    except urllib.error.URLError as exc:
        sys.exit(f"cannot reach {server}: {exc.reason}. Is the server running? (kharibulbul server -c config/server.yml)")


def _send_envelopes(envelopes: list[dict], server: str, token: str | None, out: str | None, chunk: int = 200) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            for env in envelopes:
                fh.write(json_dumps(env) + "\n")
        print(f"wrote {len(envelopes)} envelopes to {out}")
        return
    stored = 0
    for part in chunked(envelopes, chunk):
        res = _api(server, "/api/ingest", token, "POST", {"events": part})
        stored += int(res.get("stored", 0))
    print(f"sent {len(envelopes)} envelopes, server stored {stored} events")


# --------------------------------------------------------------------------- #
# sub-commands
# --------------------------------------------------------------------------- #

def cmd_server(args) -> None:
    from .server.main import run_server
    run_server(args.config)


def cmd_agent(args) -> None:
    from .agent.main import run_agent
    run_agent(args.config)


def cmd_rules(args) -> None:
    from .detect.rules import load_rules, validate_rule
    import yaml
    rules_dir = args.dir or os.path.join(project_root(), "rules")
    if args.rules_cmd == "coverage":
        cmd_coverage(args)
        return
    if args.rules_cmd == "validate":
        errors = 0
        count = 0
        import glob
        for path in sorted(glob.glob(os.path.join(rules_dir, "**", "*.y*ml"), recursive=True)):
            with open(path, "r", encoding="utf-8") as fh:
                try:
                    docs = [d for d in yaml.safe_load_all(fh) if d]
                except yaml.YAMLError as exc:
                    print(f"ERROR {path}: yaml: {exc}")
                    errors += 1
                    continue
            for data in docs:
                count += 1
                errs = validate_rule(data)
                if errs:
                    errors += 1
                    print(f"ERROR {path} [{data.get('id')}]: " + "; ".join(errs))
        rules = load_rules(rules_dir)
        ids = [r.id for r in rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            errors += 1
            print("ERROR duplicate ids: " + ", ".join(sorted(dupes)))
        print(f"{count} rules checked, {len(rules)} loadable, {errors} problem(s)")
        sys.exit(1 if errors else 0)
    if args.rules_cmd == "list":
        for r in sorted(load_rules(rules_dir), key=lambda r: r.id):
            flag = " " if r.enabled else "-"
            mitre = ",".join(m.get("technique", "") for m in r.mitre)
            print(f"{flag} {r.id:<12} {r.severity:<9} {r.kind():<9} {r.title}  [{mitre}]")
        return
    if args.rules_cmd == "test":
        from .detect.engine import DetectionEngine
        from .detect.rules import load_rule_file
        from .pipeline.pipeline import Pipeline
        from .server.api import _MemoryAlerts
        rules = load_rule_file(args.rule)
        pipeline = Pipeline({})
        mem = _MemoryAlerts()
        engine = DetectionEngine(rules, mem, default_suppress=0)
        matched = 0
        total = 0
        for env in _read_envelopes(args.events, args.dataset):
            doc = pipeline.process(env)
            if doc is None:
                continue
            total += 1
            for r in rules:
                if not r.sequence and r.prefilter(doc) and r.matches(doc):
                    matched += 1
                    if args.verbose:
                        print(f"MATCH {r.id}: {doc.get('message')}")
            engine.evaluate(doc)
        print(f"{total} events processed, {matched} selection matches, {len(mem.alerts)} alert(s)")
        for a in mem.alerts:
            print(f"  ALERT {a['rule.id']} count={a['count']} group={a['group_key']} :: {a.get('message')}")
        return


def _read_envelopes(path: str, dataset: str | None):
    """A file of raw log lines, or JSONL envelopes/documents."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.lstrip().startswith("{"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and "raw" in obj:
                        if dataset:
                            obj["dataset"] = dataset
                        yield obj
                        continue
                except json.JSONDecodeError:
                    pass
            env = {"raw": line}
            if dataset:
                env["dataset"] = dataset
            yield env


def cmd_coverage(args) -> None:
    """Scenario -> rules validation matrix (Week 3 deliverable), plus the rules no scenario exercises."""
    from .common.config import load_server_config
    from .detect.engine import DetectionEngine
    from .detect.rules import load_rules
    from .pipeline.pipeline import Pipeline
    from .server.api import _MemoryAlerts
    from .simulate.scenarios import SCENARIOS, generate
    rules_dir = args.dir or os.path.join(project_root(), "rules")
    default_cfg = os.path.join(project_root(), "config", "server.yml")
    cfg_path = args.config or (default_cfg if os.path.exists(default_cfg) else None)
    pipeline = Pipeline(load_server_config(cfg_path) if cfg_path else {})
    rules = load_rules(rules_dir)
    rows, fired_all, total_events, errors = [], set(), 0, {}
    for name, (desc, _) in SCENARIOS.items():
        mem = _MemoryAlerts()
        engine = DetectionEngine(rules, mem, default_suppress=600)
        docs = pipeline.process_many(generate([name], seed=args.seed))
        for d in docs:
            engine.evaluate(d)
        ids = sorted({a["rule.id"] for a in mem.alerts})
        fired_all |= set(ids)
        total_events += len(docs)
        errors.update(engine.snapshot()["errors"])
        rows.append((name, len(docs), ids, desc))
    never = sorted(r.id for r in rules if r.id not in fired_all)
    lines = ["# Detection validation matrix", "",
             f"Generated by `kharibulbul rules coverage` on {time.strftime('%Y-%m-%d %H:%M')} - "
             f"{len(rules)} rules, {len(SCENARIOS)} synthetic scenarios, {total_events} synthetic events "
             f"(enrichment config: {cfg_path or 'defaults'}).", "",
             "| Scenario | Events | Rules fired | Description |", "|---|---:|---|---|"]
    for name, n, ids, desc in rows:
        lines.append(f"| `{name}` | {n} | {', '.join(ids) if ids else '*(none)*'} | {desc} |")
    lines += ["", f"**Rules fired by at least one scenario:** {len(fired_all)} / {len(rules)}", ""]
    baseline = next((r for r in rows if r[0] == "baseline"), None)
    if baseline:
        lines.append(f"**Baseline noise check:** `baseline` ({baseline[1]} benign events) fired {len(baseline[2])} rule(s)"
                     + (f": {', '.join(baseline[2])}" if baseline[2] else " - quiet, as required."))
        lines.append("")
    lines += [f"## Rules not exercised by any scenario ({len(never)})", ""]
    lines += [f"- {rid}" for rid in never] or ["- (none)"]
    if errors:
        lines += ["", "## Rule evaluation errors", ""] + [f"- {k}: {v}" for k, v in errors.items()]
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.out}: {len(fired_all)}/{len(rules)} rules covered, {len(never)} never fired, "
              f"baseline alerts={len(baseline[2]) if baseline else 'n/a'}")
    else:
        print(text)
    if errors:
        sys.exit(1)


def cmd_simulate(args) -> None:
    from .simulate.scenarios import SCENARIOS, generate
    if args.list or not args.scenarios:
        print("Scenarios (safe: they only generate log records):")
        for name, (desc, _) in SCENARIOS.items():
            print(f"  {name:<22} {desc}")
        print("  all                    run every scenario")
        return
    try:
        envelopes = generate(args.scenarios, host=args.host, source_ip=args.source_ip, user=args.user,
                             spacing=args.spacing, seed=args.seed)
    except KeyError as exc:
        sys.exit(str(exc))
    print(f"generated {len(envelopes)} synthetic events for: {', '.join(args.scenarios)}")
    _send_envelopes(envelopes, args.server, args.token, args.out)


def cmd_replay(args) -> None:
    envelopes = list(_read_envelopes(args.file, args.dataset))
    if args.host:
        for env in envelopes:
            env.setdefault("host.name", args.host)
    for env in envelopes:
        env.setdefault("agent.type", "replay")
    if args.speed and not args.out:
        # stream at a fixed rate instead of one bulk post
        per_batch = max(1, int(args.speed))
        for part in chunked(envelopes, per_batch):
            _api(args.server, "/api/ingest", args.token, "POST", {"events": part})
            time.sleep(1)
        print(f"replayed {len(envelopes)} lines at ~{per_batch}/s")
        return
    _send_envelopes(envelopes, args.server, args.token, args.out)


def cmd_geoip(args) -> None:
    """GeoIP maintenance: refresh the country table, or show what enrichment returns for addresses."""
    from .common.config import load_server_config, resolve_path
    from .pipeline.geoip import GeoIP, download_country_db
    default_cfg = os.path.join(project_root(), "config", "server.yml")
    cfg = load_server_config(args.config or (default_cfg if os.path.exists(default_cfg) else None))
    geo_cfg = cfg["pipeline"].get("geoip") or {}
    db_path = resolve_path(cfg, geo_cfg.get("country_db") or "geoip/dbip-country-lite.csv.gz")
    if args.geoip_cmd == "update":
        try:
            url, size = download_country_db(args.out or db_path, args.url)
        except RuntimeError as exc:
            sys.exit(str(exc))
        print(f"downloaded {url} ({size / 1048576:.1f} MB) -> {args.out or db_path}")
        print("IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0. Restart the server to load the new table.")
        return
    geo = GeoIP(mmdb_path=resolve_path(cfg, geo_cfg["mmdb"]) if geo_cfg.get("mmdb") else None,
                custom_csv=resolve_path(cfg, geo_cfg["custom_ranges"]) if geo_cfg.get("custom_ranges") else None,
                lab_networks=cfg["pipeline"].get("lab_networks") or [], country_db=db_path)
    if args.geoip_cmd == "status":
        print(json.dumps(geo.snapshot(), indent=2))
        return
    for ip in args.ips:
        print(f"{ip}: {json.dumps(geo.lookup(ip), ensure_ascii=False)}")


def cmd_parse(args) -> None:
    from .common import ecs
    from .pipeline.pipeline import Pipeline
    pipeline = Pipeline({})
    n = 0
    nonconformant = 0
    for env in _read_envelopes(args.file, args.dataset):
        doc = pipeline.process(env)
        if doc is None:
            continue
        n += 1
        if args.check:
            problems = ecs.validate(doc)
            nonconformant += bool(problems)
            for p in problems:
                print(f"{doc.get('event.dataset')} {doc.get('event.action')}: {p}")
            continue
        if args.ecs:
            print(json.dumps(ecs.to_nested(doc), ensure_ascii=False, indent=None if args.compact else 2))
            continue
        if args.fields:
            print(json.dumps({k: doc.get(k) for k in args.fields.split(",")}, ensure_ascii=False))
        else:
            print(json.dumps(doc, ensure_ascii=False, indent=None if args.compact else 2))
        if args.limit and n >= args.limit:
            break
    if args.check:
        print(f"{n} documents checked against ECS {ecs.ECS_VERSION}: {n - nonconformant} conformant, {nonconformant} with problems")
        sys.exit(1 if nonconformant else 0)
    print(f"# {n} documents; pipeline stats: {json.dumps(pipeline.snapshot())}", file=sys.stderr)


def cmd_query(args) -> None:
    res = _api(args.server, "/api/events", args.token, params={"q": args.query, "from": args.since, "to": args.until,
                                                                "limit": args.limit, "sort": args.sort})
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return
    print(f"total={res['total']} (showing {len(res['hits'])})")
    for doc in res["hits"]:
        print(f"{doc.get('@timestamp')}  {doc.get('host.name', '-'):<12} {doc.get('event.dataset', '-'):<18} "
              f"{doc.get('event.action', '-'):<28} {str(doc.get('message', ''))[:110]}")


def cmd_alerts(args) -> None:
    if args.alerts_cmd == "escalate":
        res = _api(args.server, f"/api/alerts/{args.id}/escalate", args.token, "POST",
                   {"to": args.to, "reason": args.reason, "by": args.assignee, "notes": args.notes,
                    "raise_severity": not args.keep_severity})
        esc = res.get("escalation") or {}
        print(f"{res['id'][:12]} -> escalated (level {esc.get('level')}, to {esc.get('to')}, severity {res.get('severity')})")
        return
    if args.alerts_cmd in ("ack", "close", "fp", "investigate"):
        status = {"ack": "acknowledged", "close": "closed", "fp": "false_positive", "investigate": "investigating"}[args.alerts_cmd]
        res = _api(args.server, f"/api/alerts/{args.id}", args.token, "PATCH", {"status": status, "assignee": args.assignee, "notes": args.notes})
        print(f"{res['id'][:12]} -> {res['status']}")
        return
    res = _api(args.server, "/api/alerts", args.token, params={"status": args.status, "severity": args.severity, "limit": args.limit, "from": args.since})
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return
    for a in res["hits"]:
        print(f"{a['id'][:12]} {a['last_seen']} {a['severity'].upper():<9} {a['status']:<13} {a['rule.id']:<12} x{a['count']:<4} {a['entity']}")
    print(f"{len(res['hits'])} alert(s)")


def cmd_stats(args) -> None:
    print(json.dumps(_api(args.server, "/api/stats", args.token), indent=2))


def cmd_version(args) -> None:
    print(f"{__app_name__} {__version__}")


# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kharibulbul", description=f"{__app_name__} - from-scratch open-source mini SIEM")
    p.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--server", default=os.environ.get("KB_SERVER", "http://127.0.0.1:8080"), help="API base URL")
        sp.add_argument("--token", default=os.environ.get("KB_TOKEN"), help="API token if configured")

    s = sub.add_parser("server", help="run the Kharibulbul server (ingest + API + UI)")
    s.add_argument("-c", "--config", default=None, help="config/server.yml")
    s.set_defaults(fn=cmd_server)

    a = sub.add_parser("agent", help="run the Bülbül log agent")
    a.add_argument("-c", "--config", default=None, help="config/agent.yml")
    a.set_defaults(fn=cmd_agent)

    r = sub.add_parser("rules", help="validate / list / test detection rules")
    rs = r.add_subparsers(dest="rules_cmd", required=True)
    rv = rs.add_parser("validate")
    rv.add_argument("dir", nargs="?")
    rl = rs.add_parser("list")
    rl.add_argument("dir", nargs="?")
    rt = rs.add_parser("test", help="offline test of a rule file against a log/jsonl file")
    rt.add_argument("rule")
    rt.add_argument("events")
    rt.add_argument("--dataset")
    rt.add_argument("-v", "--verbose", action="store_true")
    rt.add_argument("dir", nargs="?")
    rc = rs.add_parser("coverage", help="run every simulate scenario offline and print the scenario -> rules validation matrix")
    rc.add_argument("dir", nargs="?")
    rc.add_argument("-c", "--config", default=None, help="server config used for enrichment (default: config/server.yml if present)")
    rc.add_argument("--out", help="write the markdown report to this file")
    rc.add_argument("--seed", type=int, default=7)
    r.set_defaults(fn=cmd_rules)

    sim = sub.add_parser("simulate", help="generate synthetic detection-test events and send them to the server")
    sim.add_argument("scenarios", nargs="*")
    sim.add_argument("--list", action="store_true")
    sim.add_argument("--host", default="ws01")
    sim.add_argument("--source-ip", default="10.10.20.55")
    sim.add_argument("--user", default="aysel")
    sim.add_argument("--spacing", type=float, default=1.0, help="seconds between generated events")
    sim.add_argument("--seed", type=int, default=None)
    sim.add_argument("--out", help="write envelopes to a JSONL file instead of sending")
    common(sim)
    sim.set_defaults(fn=cmd_simulate)

    rp = sub.add_parser("replay", help="send a log file (raw lines or JSONL envelopes) to the server")
    rp.add_argument("file")
    rp.add_argument("--dataset", help="dataset hint, e.g. linux.auth, windows.security, nginx.access")
    rp.add_argument("--host", help="host.name to attach")
    rp.add_argument("--speed", type=float, default=0, help="lines per second (0 = bulk)")
    rp.add_argument("--out")
    common(rp)
    rp.set_defaults(fn=cmd_replay)

    pa = sub.add_parser("parse", help="run the pipeline locally on a file and print ECS documents (parser debugging)")
    pa.add_argument("file")
    pa.add_argument("--dataset")
    pa.add_argument("--fields", help="comma separated fields to print")
    pa.add_argument("--limit", type=int, default=0)
    pa.add_argument("--compact", action="store_true")
    pa.add_argument("--ecs", action="store_true", help="print nested ECS objects instead of the flat documents")
    pa.add_argument("--check", action="store_true", help="validate every document against ECS and list the problems")
    pa.set_defaults(fn=cmd_parse)

    g = sub.add_parser("geoip", help="GeoIP enrichment: refresh the country table, look up addresses")
    gs = g.add_subparsers(dest="geoip_cmd", required=True)
    gu = gs.add_parser("update", help="download the current DB-IP country table (free, CC BY 4.0)")
    gu.add_argument("--url", help="download this file instead of the current month's")
    gu.add_argument("--out", help="write here instead of pipeline.geoip.country_db")
    gl = gs.add_parser("lookup", help="show the GeoIP enrichment for one or more addresses")
    gl.add_argument("ips", nargs="+")
    gt = gs.add_parser("status", help="which GeoIP sources are loaded")
    for x in (gu, gl, gt):
        x.add_argument("-c", "--config", default=None, help="server config (default: config/server.yml)")
    g.set_defaults(fn=cmd_geoip)

    q = sub.add_parser("query", help="search events through the API")
    q.add_argument("query", nargs="?", default="")
    q.add_argument("--since", default="now-24h")
    q.add_argument("--until", default=None)
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--sort", default="desc")
    q.add_argument("--json", action="store_true")
    common(q)
    q.set_defaults(fn=cmd_query)

    al = sub.add_parser("alerts", help="list or update alerts")
    als = al.add_subparsers(dest="alerts_cmd")
    for name in ("ack", "investigate", "close", "fp", "escalate"):
        x = als.add_parser(name)
        x.add_argument("id")
        x.add_argument("--assignee")
        x.add_argument("--notes")
        if name == "escalate":
            x.add_argument("--to", help="who receives the alert (default: the next tier)")
            x.add_argument("--reason", help="why it is escalated")
            x.add_argument("--keep-severity", action="store_true", help="do not raise the severity one step")
        common(x)
    al.add_argument("--status")
    al.add_argument("--severity")
    al.add_argument("--since")
    al.add_argument("--limit", type=int, default=50)
    al.add_argument("--json", action="store_true")
    common(al)
    al.set_defaults(fn=cmd_alerts)

    st = sub.add_parser("stats", help="server statistics")
    common(st)
    st.set_defaults(fn=cmd_stats)

    v = sub.add_parser("version")
    v.set_defaults(fn=cmd_version)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    main()
