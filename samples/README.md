# Sample logs

Hand-written, realistic log excerpts for parser development (Week 2) and rule testing (Week 3).
All IPs are lab/private or RFC 5737 documentation ranges.

| File | Dataset | Contains | Rules exercised |
|------|---------|----------|-----------------|
| `auth.log` | `linux.auth` | normal ops login, SSH brute force + success, sudo failures, useradd/usermod, su, curl\|bash | KB-LNX-001/002/005/010/011/012/013, KB-COR-002/003 |
| `ufw.log` | `linux.firewall` | 24 blocked ports from one source, one allowed SSH | KB-NET-002 |
| `nginx-access.log` | `nginx.access` | normal browsing, Nikto-style probing, login brute force | KB-WEB-001..005 |

## Use them

```bash
# see how the pipeline parses each line (no server needed)
kharibulbul parse samples/auth.log --dataset linux.auth --fields @timestamp,event.action,user.name,source.ip
# test one rule file offline against a sample
kharibulbul rules test rules/linux/auth.yml samples/auth.log --dataset linux.auth -v
# send to a running server (dashboards, alerts)
kharibulbul replay samples/auth.log --dataset linux.auth --host srv-web01
kharibulbul replay samples/ufw.log --dataset linux.firewall --host srv-web01
kharibulbul replay samples/nginx-access.log --dataset nginx.access --host srv-web01
```

Windows / Sysmon samples are generated on demand (they are XML and long):

```bash
kharibulbul simulate windows-brute-force lolbin --out samples/windows-events.jsonl
kharibulbul replay samples/windows-events.jsonl
```

Timestamps in the text samples are fixed (27 Sep 2026); the time-window rules still work
because the engine uses *event* time, but on the dashboards you must widen the time range
(or use `simulate`, which stamps events with the current time).
