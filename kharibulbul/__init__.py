"""Kharibulbul (Xarıbülbül) SIEM.

A from-scratch, open-source mini-SIEM built as a university blue-team project.
The name comes from the Khari Bulbul orchid (Ophrys caucasica), the flower of
Shusha / Karabakh, whose lip looks like a nightingale (bülbül) sitting in the
flower.  The SIEM "listens" to every host the way the nightingale listens.

Components
----------
kharibulbul.agent     - log shipper (files, Windows Event Log / Sysmon, journald)
kharibulbul.server    - TCP/TLS + syslog ingest, HTTP API, web dashboards
kharibulbul.pipeline  - parsers -> ECS-style normalisation -> enrichment (GeoIP, assets, intel)
kharibulbul.store     - SQLite/FTS5 event store with a small query language (+ optional OpenSearch)
kharibulbul.detect    - YAML rule engine (selections, thresholds, distinct counts, sequences)
kharibulbul.alerts    - alert lifecycle, de-duplication and notifications
kharibulbul.simulate  - synthetic detection-test event generator (safe, log-only)
"""

__version__ = "1.0.0"
__app_name__ = "Kharibulbul SIEM"
__app_name_az__ = "Xarıbülbül SIEM"
