# GeoIP enrichment

Every event with a `source.ip` / `destination.ip` gets geo fields. Three sources, checked in this order
(`kharibulbul/pipeline/geoip.py`, results cached per IP):

1. **`custom_ranges.csv`** (ours): CIDR → zone name, country, city, lat/lon, organisation. Most specific
   prefix wins. Private lab ranges are labelled (`Lab-Workstations`, `Lab-Attacker`, …) so dashboards can
   show *where in the lab* traffic comes from; any other private / loopback / link-local address gets
   `Lab-Network` (inside `pipeline.lab_networks`) or `Lab-Private`. Add your own public ranges here when
   you want a city, coordinates or an organisation name for them.
2. **MaxMind GeoLite2-City** (`GeoLite2-City.mmdb`, optional): free with a MaxMind account. Put the file
   in this folder; the server picks it up at start (needs `pip install maxminddb`). City-level detail.
3. **`dbip-country-lite.csv.gz`** – the DB-IP *IP to Country Lite* table: `start_ip,end_ip,country` for
   the whole IPv4 and IPv6 address space (~357k + ~360k ranges). It is read by our own range index
   (`CountryDB`: ranges in `array`s, bisection) – no third-party library, works fully offline.
   Every public address therefore gets at least a country and a continent.

```
kharibulbul geoip update            # download the current month's table (falls back to last month)
kharibulbul geoip lookup 8.8.4.4 94.20.20.20 10.10.99.10
kharibulbul geoip status            # which sources are loaded
GET /api/geoip/lookup?ip=8.8.4.4    # the same through the API; /api/stats -> "geoip" shows the sources
```
Restart the server after an update. DB-IP publishes a new table every month; the lab can stay offline
in between.

Fields written: `source.geo.name` (zone or country), `source.geo.country_iso_code`,
`source.geo.country_name`, `source.geo.continent_code`, `source.geo.continent_name`,
`source.geo.city_name`, `source.geo.location` (`{lat, lon}`), `source.as.organization.name` – and the
same under `destination.*`. An address that no source knows gets `geo.name: Unknown`; multicast /
unspecified / broadcast addresses get `geo.name: Reserved`.

`country_iso_code` is always ISO 3166-1 alpha-2 (ECS). For things that are not countries we use the
user-assigned codes: **`XL`** = the lab's private ranges, **`XX`** = IANA documentation ranges.

## Attribution

The country table is the free **IP to Country Lite** database by DB-IP, licensed under
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/):
*IP Geolocation by [DB-IP](https://db-ip.com)*. Keep this notice when you redistribute the file.
