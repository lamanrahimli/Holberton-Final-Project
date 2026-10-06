"""Synthetic detection-test event generator.

Nothing here touches the operating system, the network or any target: the
scenarios only *write log records* (Windows XML events, Sysmon events,
syslog lines, web-server lines) that look like the patterns our rules must
catch.  Sending them through the pipeline proves end-to-end that parsing,
normalisation, enrichment, the rule engine and the alert path all work.
"""
from .scenarios import SCENARIOS, generate  # noqa: F401
