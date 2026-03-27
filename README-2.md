# TA-triage — LLM Alert Triage for Splunk

> Enrich any Splunk alert with AI-generated triage: MITRE ATT&CK mapping, severity scoring, false positive assessment, and recommended SOC actions — using Claude or OpenAI, directly from SPL.

---

## Quick Start

```spl
index=edr sourcetype=crowdstrike:event:Detection
| triage model=claude context_fields="UserName,ComputerName,FileName,CommandLine,Technique"
| table _time, ComputerName, triage_severity_label, triage_mitre_id, triage_mitre_technique, triage_summary, triage_action
```

---

## Installation

### 1. Bundle Splunk SDK
```bash
cd TA-triage/
chmod +x get_libs.sh
./get_libs.sh
```

### 2. Install Addon
```bash
# Package
tar -czf TA-triage.spl -C .. TA-triage/

# Install via Splunk Web:
# Apps > Manage Apps > Install from file > Upload TA-triage.spl

# OR copy directly:
cp -r TA-triage/ $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

### 3. Add API Key
```
Splunk Web → Settings → Passwords → Add
  Realm:    TA-triage
  Username: triage_api_key        ← must match 'credential' option
  Password: sk-ant-api03-xxxxx    ← your Anthropic or OpenAI key
```

---

## Command Reference

```spl
| triage
    [model=<claude|openai>]          # Default: claude
    [context_fields=<field1,field2>] # Fields to send as context. Default: all non-internal
    [credential=<name>]              # Storage Passwords username. Default: triage_api_key
    [max_tokens=<int>]               # 100-2000. Default: 700
    [include_raw=<true|false>]       # Include _raw field. Default: false
    [timeout=<seconds>]              # API timeout. Default: 30
```

---

## Output Fields

| Field | Description |
|-------|-------------|
| `triage_severity` | Numeric score 1-10 |
| `triage_severity_label` | Critical / High / Medium / Low / Informational |
| `triage_mitre_id` | ATT&CK technique ID (e.g. T1059.001) |
| `triage_mitre_technique` | Technique name (e.g. PowerShell) |
| `triage_mitre_tactic` | ATT&CK tactic (e.g. Execution) |
| `triage_summary` | 2-3 sentence AI analysis |
| `triage_action` | Recommended SOC analyst action |
| `triage_fp_likelihood` | Low / Medium / High |
| `triage_fp_reason` | Reason for FP assessment |
| `triage_kill_chain` | Kill chain phase |
| `triage_iocs` | Comma-separated extracted IOCs |
| `triage_model` | Model used |
| `triage_latency_ms` | API call latency |
| `triage_status` | success / error |
| `triage_error` | Error message if status=error |

---

## Real-World SPL Examples

### EDR Alert Triage (CrowdStrike)
```spl
index=edr sourcetype=crowdstrike:event:Detection EventType=DetectionSummaryEvent
| triage model=claude context_fields="UserName,ComputerName,FileName,FilePath,CommandLine,Technique,Tactic,Severity"
| where triage_severity >= 7
| table _time, ComputerName, UserName, triage_severity_label, triage_mitre_id, triage_mitre_technique, triage_summary, triage_action
| sort -triage_severity
```

### SIEM Alert Enrichment
```spl
index=notable source=*correlation_searches*
| triage model=claude context_fields="rule_name,src,dest,src_user,mitre_technique_id,risk_score"
| table _time, rule_name, triage_severity_label, triage_fp_likelihood, triage_summary, triage_action
```

### Bulk Triage with Stats
```spl
index=alerts earliest=-24h
| triage model=claude
| stats count by triage_severity_label, triage_mitre_tactic
| sort -count
```

### False Positive Hunt
```spl
index=alerts
| triage model=claude context_fields="alert_name,src_ip,dest_ip,user,process"
| where triage_fp_likelihood="High"
| table _time, alert_name, triage_fp_reason, triage_summary
```

### SOAR Trigger (pipe to | req)
```spl
index=alerts triage_status=success triage_severity>=8
| triage model=claude
| eval payload=json_object("alert_id", id, "summary", triage_summary, "action", triage_action, "mitre", triage_mitre_id)
| req url="https://soar.internal/api/create_case" method=POST body=payload credential=soar_webhook
```

---

## Alert Action: Auto-Triage

You can trigger triage automatically from Splunk alerts. Configure any Splunk Scheduled Search to pipe results through `| triage` before notifying or creating tickets.

---

## Architecture

```
SPL Pipeline → triage.py (StreamingCommand)
                    ↓
          Splunk Storage Passwords
          (API key retrieval)
                    ↓
          Event field extraction
          (context_fields filter)
                    ↓
          Anthropic Claude API
          OR OpenAI API
                    ↓
          JSON response parsing
                    ↓
          Enriched event fields
          (triage_* fields added)
```

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 1.0.0 | 2026-03-27 | Initial release: Claude + OpenAI, MITRE mapping, FP scoring |

---

## Roadmap

- [ ] v1.1 — Batch processing (send N events per API call)
- [ ] v1.1 — Caching layer (same alert → skip API call)
- [ ] v1.2 — Local LLM support (Ollama endpoint)
- [ ] v1.2 — Custom prompt templates via `triage_prompts.conf`
- [ ] v1.3 — SOAR playbook suggestion
- [ ] v1.3 — Evidence package export (NIST CSF / NIS2 field mapping)

---

## Author

Detection Engineering Add-on  
Built for Splunk Enterprise 9.x+ and Splunk Cloud
