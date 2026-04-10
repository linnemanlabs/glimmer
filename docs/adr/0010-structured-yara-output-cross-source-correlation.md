**Date:** 2026-04-09
**Status:** Accepted
**Context:** Wazuh's active response triggers YARA scans on FIM events, but the detection results need to be both human-readable in the SIEM and machine-parseable for automated correlation with other data sources (auditd, network logs). Wazuh's built-in `ar_log_json` decoder doesn't extract nested custom JSON fields cleanly, and the standard `active-responses.log` format doesn't support structured fields.
 
**Decision:** Write YARA scan results as single-line JSON to a dedicated `/var/ossec/logs/yara.log` with a fixed schema: `{"timestamp", "yara": {"rule", "file", "sha256", "confidence", "severity", "mitre_attack_id", "mitre_technique"}}`. Wazuh's built-in JSON decoder parses this automatically into `data.yara.*` fields. A separate human-readable line still goes to `active-responses.log` for operational logging. Custom Wazuh rules chain off `<decoded_as>json</decoded_as>` with `<field name="yara.rule">` matching.
 
**Consequences:**
- All YARA metadata (confidence, severity, MITRE ATT&CK mapping, file hash) indexed as structured fields in OpenSearch
- Cross-source correlation possible: `data.yara.file` from YARA alerts can be joined with `data.audit.exe` from auditd alerts
- Single OpenSearch aggregation query identifies binaries flagged by both YARA and auditd
- JSON format is also consumable by Loki/promtail for parallel ingestion into the observability stack
- Each YARA rule ID (100101-100106) maps to a specific detection with its own severity level
- SHA-256 hash captured at scan time enables IOC sharing and threat intel integration even if the binary is later deleted
- Custom decoder not needed, Wazuh's built-in JSON decoder handles the parsing
 