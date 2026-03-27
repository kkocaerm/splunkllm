#!/usr/bin/env python3
"""
TA-triage | triage Command
LLM-powered alert triage for Splunk
Author: Detection Engineering Add-on
Version: 1.0.0

Usage:
    index=alerts sourcetype=edr
    | triage model=claude context_fields="src_ip,dest_ip,process_name,alert_name"
    
    index=alerts
    | triage model=openai credential=openai_key context_fields="user,host,action"
"""

import sys
import os
import json
import time
import urllib.request
import urllib.error
import re

# Splunk SDK path — bundled in lib/ or system
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

from splunklib.searchcommands import (
    dispatch, StreamingCommand, Configuration, Option, validators
)

# ─────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL   = "claude-sonnet-4-20250514"
OPENAI_API_URL    = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL      = "gpt-4o-mini"

# ─────────────────────────────────────────────
# System Prompt (SOC Analyst persona)
# ─────────────────────────────────────────────
TRIAGE_SYSTEM_PROMPT = """You are an expert SOC analyst and detection engineer with deep knowledge of MITRE ATT&CK, threat hunting, and incident response.

Analyze the provided security alert data and return ONLY a valid JSON object with exactly these keys:

{
  "severity": <integer 1-10>,
  "severity_label": "<Critical|High|Medium|Low|Informational>",
  "mitre_technique_id": "<e.g. T1059.001>",
  "mitre_technique_name": "<e.g. PowerShell>",
  "mitre_tactic": "<e.g. Execution>",
  "triage_summary": "<2-3 sentence analysis of what happened, context, and risk>",
  "recommended_action": "<specific, actionable next step for SOC analyst>",
  "false_positive_likelihood": "<Low|Medium|High>",
  "false_positive_reason": "<brief reason for FP assessment>",
  "ioc_extracted": ["<any IOC found: IP, hash, domain, user>"],
  "kill_chain_phase": "<Reconnaissance|Weaponization|Delivery|Exploitation|Installation|Command & Control|Actions on Objectives>"
}

Rules:
- Respond ONLY with JSON. No markdown. No explanation. No preamble.
- Be specific and technical. Avoid generic statements.
- Base severity on potential business impact AND attacker capability required.
- If data is insufficient for a field, use empty string "" or empty array [].
"""


# ─────────────────────────────────────────────
# Splunk Internal Fields to Exclude
# ─────────────────────────────────────────────
SPLUNK_INTERNAL_FIELDS = {
    '_raw', '_time', '_indextime', '_cd', '_si', '_sourcetype',
    'punct', 'linecount', 'splunk_server', 'splunk_server_group',
    'date_hour', 'date_mday', 'date_minute', 'date_month',
    'date_second', 'date_wday', 'date_year', 'date_zone',
    'eventtype', 'tag', 'search_name'
}


@Configuration()
class TriageCommand(StreamingCommand):
    """
    | triage — LLM-Powered Alert Triage

    Enriches each event with AI-generated triage: MITRE technique mapping,
    severity scoring, recommended actions, and false positive assessment.

    Credentials must be stored in Splunk Storage Passwords:
        App: TA-triage
        Username: triage_api_key   (or custom via credential= option)
        Password: <your API key>

    Examples:
        | triage
        | triage model=claude context_fields="src_ip,dest_ip,process_name,alert_name"
        | triage model=openai credential=openai_key max_tokens=800
        | triage model=claude context_fields="user,host,cmd_line" include_raw=true
    """

    model = Option(
        doc='LLM provider: claude (default) or openai',
        name='model',
        require=False,
        default='claude'
    )

    context_fields = Option(
        doc='Comma-separated field names to send as context. If empty, sends all non-internal fields.',
        name='context_fields',
        require=False,
        default=''
    )

    credential = Option(
        doc='Credential name in Splunk Storage Passwords (username field). Default: triage_api_key',
        name='credential',
        require=False,
        default='triage_api_key'
    )

    max_tokens = Option(
        doc='Max tokens for LLM response (default: 700)',
        name='max_tokens',
        require=False,
        default=700,
        validate=validators.Integer(minimum=100, maximum=2000)
    )

    include_raw = Option(
        doc='Include _raw field in context (default: false)',
        name='include_raw',
        require=False,
        default=False,
        validate=validators.Boolean()
    )

    timeout = Option(
        doc='API call timeout in seconds (default: 30)',
        name='timeout',
        require=False,
        default=30,
        validate=validators.Integer(minimum=5, maximum=120)
    )

    # ─────────────────────────────────────────
    # Credential Retrieval
    # ─────────────────────────────────────────
    def _get_api_key(self, credential_name):
        """Retrieve API key from Splunk Storage Passwords."""
        try:
            for cred in self.service.storage_passwords:
                # Match by username (credential name)
                if cred.content.get('username') == credential_name:
                    return cred.content.get('clear_password', '').strip()
        except Exception as e:
            self.logger.error(f"[TA-triage] Credential retrieval failed: {e}")
        return None

    # ─────────────────────────────────────────
    # Context Building
    # ─────────────────────────────────────────
    def _build_context(self, record):
        """Extract relevant fields from event for LLM context."""
        if self.context_fields:
            fields = [f.strip() for f in self.context_fields.split(',') if f.strip()]
            context = {}
            for f in fields:
                val = record.get(f)
                if val is not None:
                    context[f] = val
        else:
            # Auto-select: exclude Splunk internal fields
            context = {}
            for k, v in record.items():
                if k in SPLUNK_INTERNAL_FIELDS:
                    continue
                if k.startswith('_') and k != '_raw':
                    continue
                if k == '_raw' and not self.include_raw:
                    continue
                context[k] = v

        return json.dumps(context, indent=2, default=str)

    # ─────────────────────────────────────────
    # Claude API Call
    # ─────────────────────────────────────────
    def _call_claude(self, api_key, context):
        payload = {
            "model": ANTHROPIC_MODEL,
            "max_tokens": int(self.max_tokens),
            "system": TRIAGE_SYSTEM_PROMPT,
            "messages": [
                {
                    "role": "user",
                    "content": f"Triage this security alert event:\n\n```json\n{context}\n```"
                }
            ]
        }

        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            ANTHROPIC_API_URL,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01'
            }
        )

        with urllib.request.urlopen(req, timeout=int(self.timeout)) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result['content'][0]['text']

    # ─────────────────────────────────────────
    # OpenAI API Call
    # ─────────────────────────────────────────
    def _call_openai(self, api_key, context):
        payload = {
            "model": OPENAI_MODEL,
            "max_tokens": int(self.max_tokens),
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Triage this security alert event:\n\n```json\n{context}\n```"
                }
            ]
        }

        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            OPENAI_API_URL,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}'
            }
        )

        with urllib.request.urlopen(req, timeout=int(self.timeout)) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result['choices'][0]['message']['content']

    # ─────────────────────────────────────────
    # Parse LLM Response
    # ─────────────────────────────────────────
    def _parse_response(self, raw_text):
        """Extract JSON from LLM response, handling markdown fences."""
        text = raw_text.strip()

        # Strip markdown code fences if present
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
        if json_match:
            text = json_match.group(1)

        return json.loads(text)

    # ─────────────────────────────────────────
    # Main Stream Processing
    # ─────────────────────────────────────────
    def stream(self, records):
        # Retrieve API key once per search
        api_key = self._get_api_key(self.credential)

        if not api_key:
            self.logger.error(
                f"[TA-triage] Credential '{self.credential}' not found in Storage Passwords. "
                f"Add via: Settings > Passwords > Add"
            )
            for record in records:
                record['triage_status'] = 'error'
                record['triage_error'] = (
                    f"API key '{self.credential}' not found. "
                    f"Add via Splunk Settings > Passwords > Add."
                )
                yield record
            return

        model_lower = self.model.lower()
        self.logger.info(f"[TA-triage] Starting triage with model={model_lower}")

        for record in records:
            start_time = time.time()
            try:
                # Build context from event
                context = self._build_context(record)

                # Call LLM
                if model_lower == 'claude':
                    raw_response = self._call_claude(api_key, context)
                elif model_lower == 'openai':
                    raw_response = self._call_openai(api_key, context)
                else:
                    raise ValueError(f"Unsupported model: {self.model}. Use 'claude' or 'openai'.")

                # Parse JSON response
                triage = self._parse_response(raw_response)

                # Enrich event
                record['triage_severity']          = triage.get('severity', '')
                record['triage_severity_label']    = triage.get('severity_label', '')
                record['triage_mitre_id']          = triage.get('mitre_technique_id', '')
                record['triage_mitre_technique']   = triage.get('mitre_technique_name', '')
                record['triage_mitre_tactic']      = triage.get('mitre_tactic', '')
                record['triage_summary']           = triage.get('triage_summary', '')
                record['triage_action']            = triage.get('recommended_action', '')
                record['triage_fp_likelihood']     = triage.get('false_positive_likelihood', '')
                record['triage_fp_reason']         = triage.get('false_positive_reason', '')
                record['triage_kill_chain']        = triage.get('kill_chain_phase', '')
                record['triage_iocs']              = ', '.join(triage.get('ioc_extracted', []))
                record['triage_model']             = self.model
                record['triage_latency_ms']        = int((time.time() - start_time) * 1000)
                record['triage_status']            = 'success'

            except urllib.error.HTTPError as e:
                body = e.read().decode('utf-8', errors='replace')
                self.logger.error(f"[TA-triage] HTTP {e.code}: {body[:500]}")
                record['triage_status'] = 'error'
                record['triage_error']  = f"API error {e.code}: {e.reason}"

            except urllib.error.URLError as e:
                self.logger.error(f"[TA-triage] URL error: {e.reason}")
                record['triage_status'] = 'error'
                record['triage_error']  = f"Network error: {e.reason}"

            except json.JSONDecodeError as e:
                self.logger.error(f"[TA-triage] JSON parse failed: {e}")
                record['triage_status'] = 'error'
                record['triage_error']  = f"JSON parse error: {str(e)}"

            except Exception as e:
                self.logger.error(f"[TA-triage] Unexpected error: {e}")
                record['triage_status'] = 'error'
                record['triage_error']  = str(e)

            yield record


if __name__ == '__main__':
    dispatch(TriageCommand, sys.argv, sys.stdin, sys.stdout, __name__)
