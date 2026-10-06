# Kharibulbul response playbooks

Every detection rule links to one of these playbooks (`playbook:` field). The Alerts
page opens the playbook next to the alert. Each playbook follows the same structure:

1. **Trigger** – which rules and what the alert means
2. **Severity & SLA** – how fast the on-duty analyst must react (lab targets)
3. **Triage** – queries to run in the Events page (Kharibulbul query language) to confirm
4. **Containment** – stop the bleeding
5. **Eradication & recovery** – remove the cause, restore normal state
6. **Evidence** – what to export for the report (`kharibulbul query --json`, alert JSON)
7. **False positives & tuning** – how to adjust the rule if it was benign
8. **Close-out** – status changes and notes in the alert

| Playbook | Covers |
|----------|--------|
| [PB-001 Brute force & suspicious logons](PB-001-brute-force.md) | KB-WIN-001..008, KB-LNX-001/002/003/004/005/021, KB-WEB-002, KB-NET-030/033, KB-COR-001/002 |
| [PB-002 Scanning, web attacks, availability](PB-002-port-scan.md) | KB-NET-001..004, KB-NET-031/032, KB-WEB-001/003/004/005/006/007/008, KB-COR-004 |
| [PB-003 LOLBins & PowerShell](PB-003-lolbin.md) | KB-SYS-010..018, KB-SYS-020, KB-PS-001/002 |
| [PB-004 Accounts & privileges](PB-004-new-account.md) | KB-WIN-010..013, KB-LNX-011/012, KB-COR-003 |
| [PB-005 Log clearing / sensor tampering / data quality](PB-005-log-cleared.md) | KB-WIN-020..022/024, KB-SYS-071/072, KB-LNX-022, KB-KB-001/002 |
| [PB-007 Malware & credential access](PB-007-malware.md) | KB-WIN-023, KB-SYS-030/040/041/050/060/061, KB-PS-003, KB-TI-003, KB-COR-007 |
| [PB-008 Persistence](PB-008-persistence.md) | KB-WIN-030..033, KB-SYS-070, KB-LNX-016, KB-COR-006 |
| [PB-009 C2 / beaconing](PB-009-c2-beacon.md) | KB-NET-005/010..014/020/021, KB-TI-001/002, KB-COR-005 |
| [PB-010 Linux privilege escalation](PB-010-linux-privesc.md) | KB-LNX-010/013/014/015/017/020 |

Rules in `rules/team/` (KB-WIN-007/008, KB-COR-006/007, KB-SYS-072, KB-NET-005/014/030..033, KB-LNX-017/020..022,
KB-WEB-006..008) were written in Week 3 on top of the base set.

Alert statuses: `new → acknowledged → investigating → closed | false_positive`.
Use `kharibulbul alerts ack <id> --assignee <name>` or the Alerts page buttons.
