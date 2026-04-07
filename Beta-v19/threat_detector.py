"""
Active Threat Detector — ByteIT SentinelX
==========================================
Continuously scans OpenSearch for high/critical alerts that are NOT buried
in noise suppression filters, classifies them as "Active Threat Detected",
and immediately blasts an email to every configured alert recipient.

Design goals
------------
- Only triggers for rule.level >= 12 (HIGH = 12-14, CRITICAL = 15+)
- Deduplicates against ActiveThreatNotification records so each alert fires
  exactly one email notification per unique OpenSearch _id.
- Collects recipients from ALL enabled AlertConfig rows (union, deduplicated).
- Sends a rich, actionable HTML email with severity, agent context, threat
  indicators, MITRE mappings, and recommended actions.
- Integrates with the existing EmailAlerts.send_alert_email() infrastructure
  so SMTP credentials and settings are shared.
"""

import json
import logging
import os
import base64
import datetime

logger = logging.getLogger(__name__)

# Wazuh rule levels
LEVEL_HIGH     = 12
LEVEL_CRITICAL = 15

# Severity labels
def _level_to_severity(level: int) -> str:
    if level >= LEVEL_CRITICAL:
        return 'CRITICAL'
    if level >= LEVEL_HIGH:
        return 'HIGH'
    return 'MEDIUM'

def _level_to_color(level: int) -> str:
    if level >= LEVEL_CRITICAL:
        return '#dc2626'   # deep red
    if level >= LEVEL_HIGH:
        return '#ea580c'   # orange-red
    return '#d97706'       # amber

# ---------------------------------------------------------------------------
# Public entry point — called by the scheduler every 2 min
# ---------------------------------------------------------------------------

def scan_for_active_threats():
    """
    Scan the last 5 minutes of OpenSearch alerts for level >= 12 events
    that have not yet been notified.  For each new threat: persist a
    notification record, then email all configured recipients.
    """
    try:
        from opensearch_api import OpenSearchAPI
        from models import db, AlertConfig, ActiveThreatNotification

        api = OpenSearchAPI()
        if not api.client:
            logger.warning('Active threat scan skipped — OpenSearch unavailable')
            return

        since = (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat()

        query = {
            'size': 50,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {'range': {'@timestamp': {'gte': since}}},
                        {'range': {'rule.level': {'gte': LEVEL_HIGH}}},
                    ]
                }
            }
        }

        try:
            resp = api.client.search(index='wazuh-alerts-*', body=query,
                                     request_timeout=20)
        except Exception as exc:
            logger.error(f'Active threat OpenSearch query failed: {exc}')
            return

        hits = resp.get('hits', {}).get('hits', [])
        if not hits:
            logger.debug('Active threat scan: no level>=12 alerts in last 5m')
            return

        logger.info(f'Active threat scan: found {len(hits)} potential threat(s)')

        recipients = _collect_all_recipients()
        if not recipients:
            logger.warning('Active threat scan: no email recipients configured — skipping notification')

        new_count = 0
        for hit in hits:
            alert_id = hit.get('_id', '')
            if not alert_id:
                continue

            # Dedup check
            existing = ActiveThreatNotification.query.filter_by(
                alert_id=alert_id
            ).first()
            if existing:
                continue

            source  = hit.get('_source', {})
            rule    = source.get('rule', {})
            level   = int(rule.get('level', 0))
            if level < LEVEL_HIGH:
                continue

            # Persist notification record immediately (even before email send)
            threat = ActiveThreatNotification(
                alert_id        = alert_id,
                rule_id         = str(rule.get('id', '')),
                rule_level      = level,
                rule_description= rule.get('description', ''),
                agent_name      = source.get('agent', {}).get('name', ''),
                agent_id        = source.get('agent', {}).get('id', ''),
                agent_ip        = source.get('agent', {}).get('ip', ''),
                severity        = _level_to_severity(level),
                detected_at     = datetime.datetime.utcnow(),
                raw_alert_json  = json.dumps(source)[:4000],
                notification_sent     = False,
                recipients_notified   = '',
            )
            db.session.add(threat)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                continue

            # Send email(s)
            if recipients:
                sent_ok, err = _send_active_threat_email(source, recipients)
                threat.notification_sent   = sent_ok
                threat.notification_sent_at = datetime.datetime.utcnow()
                threat.recipients_notified  = ','.join(recipients)
                if not sent_ok:
                    logger.error(f'Active threat email failed for {alert_id}: {err}')
                else:
                    logger.info(f'Active threat email sent for rule {rule.get("id")} on {source.get("agent",{}).get("name","?")} → {recipients}')
                db.session.commit()

            new_count += 1

        if new_count:
            logger.info(f'Active threat scan complete: {new_count} new threat(s) notified')

    except Exception as exc:
        logger.error(f'scan_for_active_threats error: {exc}', exc_info=True)


# ---------------------------------------------------------------------------
# Recipient collection
# ---------------------------------------------------------------------------

def _collect_all_recipients() -> list:
    """Return a deduplicated list of all email_recipient values from every
    enabled AlertConfig, plus the ThreatIntelConfig recipient if set."""
    from models import AlertConfig
    emails = set()
    try:
        configs = AlertConfig.query.filter_by(enabled=True).all()
        for cfg in configs:
            for addr in str(cfg.email_recipient).split(','):
                addr = addr.strip()
                if addr and '@' in addr:
                    emails.add(addr)
    except Exception as exc:
        logger.error(f'Could not collect alert recipients: {exc}')

    # Also pull from ThreatIntelConfig if available
    try:
        from models import ThreatIntelConfig
        ti_cfg = ThreatIntelConfig.get_config()
        if ti_cfg and ti_cfg.email_recipient:
            for addr in str(ti_cfg.email_recipient).split(','):
                addr = addr.strip()
                if addr and '@' in addr:
                    emails.add(addr)
    except Exception:
        pass

    return list(emails)


# ---------------------------------------------------------------------------
# Email builder
# ---------------------------------------------------------------------------

def _send_active_threat_email(source: dict, recipients: list):
    """
    Build and send a rich HTML email for a detected active threat.
    Returns (success: bool, error: str).
    """
    try:
        from email_alerts import EmailAlerts
        ea = EmailAlerts()

        rule     = source.get('rule', {})
        agent    = source.get('agent', {})
        data_sec = source.get('data', {})
        data_win = data_sec.get('win', {})
        eventdata= data_win.get('eventdata', {})

        level    = int(rule.get('level', 0))
        sev      = _level_to_severity(level)
        color    = _level_to_color(level)

        rule_id  = str(rule.get('id', '—'))
        rule_desc= rule.get('description', 'Unknown threat detected')
        agent_nm = agent.get('name', '—')
        agent_ip = agent.get('ip', '—')
        agent_id = agent.get('id', '—')
        location = (agent.get('labels') or {})
        loc_str  = ', '.join(f'{k}: {v}' for k, v in
                             {k: (v or {}).get('set','') for k,v in location.items()}.items()
                             if v) if isinstance(location, dict) else ''

        ts_raw   = source.get('@timestamp', source.get('timestamp', ''))
        try:
            ts_dt = datetime.datetime.fromisoformat(ts_raw.replace('Z','+00:00'))
            ts_str = ts_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            ts_str = ts_raw or 'Unknown'

        # Extract threat-specific fields
        threat_name   = (eventdata.get('threatName')     or
                         eventdata.get('threat Name')    or '')
        process_name  = (eventdata.get('processName')    or
                         eventdata.get('process Name')   or
                         data_sec.get('process', {}).get('name', '') or '')
        file_path     = (eventdata.get('path')           or
                         eventdata.get('filePath')       or '')
        severity_name = (eventdata.get('severityName')   or
                         eventdata.get('severity Name')  or sev)
        category_name = (eventdata.get('categoryName')   or
                         eventdata.get('category Name')  or '')
        detection_user= (eventdata.get('detectionUser')  or
                         eventdata.get('detection User') or '')

        # MITRE / compliance
        mitre  = rule.get('mitre',  {})
        pci    = rule.get('pci_dss', [])
        hipaa  = rule.get('hipaa',  [])
        nist   = rule.get('nist_800_53', [])
        mitre_ids = mitre.get('id', []) if isinstance(mitre.get('id'), list) else []
        mitre_tac = mitre.get('tactic', []) if isinstance(mitre.get('tactic'), list) else []

        # Recommended actions by threat type
        recs = _get_recommended_actions(rule_id, rule_desc, level)

        # Subject line
        threat_label = threat_name or rule_desc[:60]
        subject = f"🚨 ACTIVE THREAT DETECTED [{sev}] — {threat_label} on {agent_nm}"

        logo_uri = _load_logo_b64()
        logo_img = (f'<img src="{logo_uri}" alt="ByteIT" '
                    f'style="height:36px;margin-bottom:12px">'
                    if logo_uri else
                    '<span style="font-size:18px;font-weight:800;color:#60a5fa">ByteIT SentinelX</span>')

        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Active Threat Detected</title></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:Arial,sans-serif;color:#e5e7eb">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:24px 0">
  <tr><td align="center">
  <table width="640" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;overflow:hidden;border:1px solid #1e2535">

    <!-- Logo header -->
    <tr>
      <td style="background:#0d1117;padding:20px 28px;border-bottom:1px solid #1e2535">
        {logo_img}
      </td>
    </tr>

    <!-- Threat banner -->
    <tr>
      <td style="background:{color};padding:24px 28px">
        <div style="font-size:13px;font-weight:700;letter-spacing:2px;color:#fff;opacity:.85;text-transform:uppercase;margin-bottom:6px">
          ⚠ Active Threat Detected in Your Network
        </div>
        <div style="font-size:28px;font-weight:800;color:#fff;line-height:1.1;margin-bottom:6px">
          {sev} — {rule_desc}
        </div>
        <div style="font-size:13px;color:#fff;opacity:.9">
          Detection Time: {ts_str}
        </div>
      </td>
    </tr>

    <!-- Severity badge row -->
    <tr>
      <td style="padding:20px 28px 0">
        <table cellpadding="0" cellspacing="0">
          <tr>
            <td style="background:{color};color:#fff;font-size:11px;font-weight:800;letter-spacing:1px;text-transform:uppercase;padding:4px 12px;border-radius:20px">
              {sev}
            </td>
            <td style="width:12px"></td>
            <td style="background:#1e2535;color:#9ca3af;font-size:11px;font-weight:700;padding:4px 12px;border-radius:20px">
              Rule {rule_id} · Level {level}
            </td>
            {"<td style='width:12px'></td><td style='background:#1f2937;color:#d1d5db;font-size:11px;font-weight:700;padding:4px 12px;border-radius:20px'>" + category_name + "</td>" if category_name else ""}
          </tr>
        </table>
      </td>
    </tr>

    <!-- Affected agent -->
    <tr>
      <td style="padding:20px 28px 0">
        <div style="background:#1a2035;border:1px solid #1e2535;border-radius:8px;padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;margin-bottom:10px;font-weight:700">
            Affected Agent
          </div>
          <table width="100%" cellpadding="4" cellspacing="0">
            <tr>
              <td style="color:#9ca3af;font-size:13px;width:120px">Agent Name</td>
              <td style="color:#f3f4f6;font-size:13px;font-weight:600">{agent_nm}</td>
            </tr>
            <tr>
              <td style="color:#9ca3af;font-size:13px">Agent IP</td>
              <td style="color:#f3f4f6;font-size:13px">{agent_ip}</td>
            </tr>
            <tr>
              <td style="color:#9ca3af;font-size:13px">Agent ID</td>
              <td style="color:#f3f4f6;font-size:13px">{agent_id}</td>
            </tr>
            {"<tr><td style='color:#9ca3af;font-size:13px'>Location</td><td style='color:#f3f4f6;font-size:13px'>" + loc_str + "</td></tr>" if loc_str else ""}
          </table>
        </div>
      </td>
    </tr>

    <!-- Threat context -->
    {"" if not (threat_name or process_name or file_path or detection_user) else f'''
    <tr>
      <td style="padding:16px 28px 0">
        <div style="background:#1f0e0e;border:1px solid #7f1d1d;border-radius:8px;padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#f87171;margin-bottom:10px;font-weight:700">
            Threat Intelligence
          </div>
          <table width="100%" cellpadding="4" cellspacing="0">
            {"<tr><td style='color:#9ca3af;font-size:13px;width:120px'>Threat Name</td><td style='color:#fca5a5;font-size:13px;font-weight:700'>" + threat_name + "</td></tr>" if threat_name else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>Process</td><td style='color:#fcd34d;font-size:12px;font-family:monospace'>" + process_name + "</td></tr>" if process_name else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>Path / File</td><td style='color:#fcd34d;font-size:12px;font-family:monospace'>" + file_path + "</td></tr>" if file_path else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>Severity Name</td><td style='color:#f3f4f6;font-size:13px'>" + severity_name + "</td></tr>" if severity_name and severity_name != sev else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>Detection User</td><td style='color:#f3f4f6;font-size:13px'>" + detection_user + "</td></tr>" if detection_user else ""}
          </table>
        </div>
      </td>
    </tr>
    '''}

    <!-- MITRE / Compliance -->
    {"" if not (mitre_ids or mitre_tac or pci or nist or hipaa) else f'''
    <tr>
      <td style="padding:16px 28px 0">
        <div style="background:#0c1a0c;border:1px solid #14532d;border-radius:8px;padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#86efac;margin-bottom:10px;font-weight:700">
            Compliance &amp; Framework Mappings
          </div>
          <table width="100%" cellpadding="4" cellspacing="0">
            {"<tr><td style='color:#9ca3af;font-size:13px;width:120px'>MITRE ATT&amp;CK</td><td style='color:#f3f4f6;font-size:13px'>" + ", ".join(mitre_ids) + "</td></tr>" if mitre_ids else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>Tactics</td><td style='color:#f3f4f6;font-size:13px'>" + ", ".join(mitre_tac) + "</td></tr>" if mitre_tac else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>PCI-DSS</td><td style='color:#f3f4f6;font-size:13px'>" + ", ".join(pci) + "</td></tr>" if pci else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>NIST 800-53</td><td style='color:#f3f4f6;font-size:13px'>" + ", ".join(nist) + "</td></tr>" if nist else ""}
            {"<tr><td style='color:#9ca3af;font-size:13px'>HIPAA</td><td style='color:#f3f4f6;font-size:13px'>" + ", ".join(hipaa) + "</td></tr>" if hipaa else ""}
          </table>
        </div>
      </td>
    </tr>
    '''}

    <!-- Recommended actions -->
    <tr>
      <td style="padding:16px 28px 0">
        <div style="background:#0f1a2e;border:1px solid #1e3a5f;border-radius:8px;padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#93c5fd;margin-bottom:10px;font-weight:700">
            Recommended Immediate Actions
          </div>
          {"".join(f"<div style='color:#e5e7eb;font-size:13px;padding:3px 0'>→ {r}</div>" for r in recs)}
        </div>
      </td>
    </tr>

    <!-- Action links -->
    <tr>
      <td style="padding:20px 28px">
        <table cellpadding="0" cellspacing="0">
          <tr>
            <td>
              <a href="#" style="background:{color};color:#fff;text-decoration:none;padding:10px 22px;border-radius:6px;font-size:13px;font-weight:700;display:inline-block">
                View in SentinelX Dashboard
              </a>
            </td>
            <td style="width:12px"></td>
            <td>
              <a href="#" style="background:#1e2535;color:#93c5fd;text-decoration:none;padding:10px 22px;border-radius:6px;font-size:13px;font-weight:700;display:inline-block;border:1px solid #1e3a5f">
                Open ITDR Investigation
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background:#0d1117;padding:16px 28px;border-top:1px solid #1e2535">
        <div style="color:#6b7280;font-size:11px">
          This is an automated <strong style="color:#9ca3af">Active Threat Detection</strong> alert from
          <strong style="color:#60a5fa">ByteIT SentinelX</strong> SOC Platform.
          Severity level {level} threshold triggered at {ts_str}.
          Do not reply to this email. Contact your SOC team for immediate response.
        </div>
      </td>
    </tr>

  </table>
  </td></tr>
</table>
</body>
</html>"""

        recipient_str = ', '.join(recipients)
        success, err = ea.send_alert_email(recipient_str, subject, html)
        return success, err

    except Exception as exc:
        logger.error(f'_send_active_threat_email exception: {exc}', exc_info=True)
        return False, str(exc)


# ---------------------------------------------------------------------------
# Recommended actions lookup
# ---------------------------------------------------------------------------

def _get_recommended_actions(rule_id: str, description: str, level: int) -> list:
    desc_lower = description.lower()

    # Malware / HackTool (Windows Defender, Wazuh malware)
    if any(kw in desc_lower for kw in ['malware', 'hacktool', 'virus', 'trojan', 'ransomware', 'spyware', 'adware', 'kmspico', 'autokms', 'antimalware']):
        return [
            'IMMEDIATELY isolate the affected agent from the network',
            'Run a full Windows Defender / EDR scan on the affected endpoint',
            'Review recently installed software and remove any unlicensed tools (e.g. KMSpico)',
            'Check for lateral movement — review other agents in the same subnet',
            'Revoke and rotate credentials used on the affected endpoint',
            'Capture and preserve forensic image before remediation',
            'Escalate to Tier-2 SOC analyst for incident response',
        ]

    # Privilege escalation
    if any(kw in desc_lower for kw in ['privilege', 'escalation', 'admin', 'sudo', 'runas']):
        return [
            'Review the account that triggered the privilege escalation',
            'Verify if the escalation was authorised by change management',
            'Check for credential dumping tools (Mimikatz, etc.) on the agent',
            'Disable the account temporarily if unauthorised',
            'Review group membership changes in Active Directory',
        ]

    # Authentication / brute force
    if any(kw in desc_lower for kw in ['login', 'authentication', 'failed', 'brute', 'lockout', 'password']):
        return [
            'Identify the source IP and check for geolocation anomaly',
            'Block the source IP at the firewall if not a known corporate IP',
            'Verify if MFA is enforced for the targeted account',
            'Review the last 24h of login history for the account',
            'Consider temporarily locking the targeted account',
        ]

    # Network / intrusion
    if any(kw in desc_lower for kw in ['scan', 'intrusion', 'exploit', 'shellshock', 'sql injection', 'xss', 'rce']):
        return [
            'Block the source IP immediately at perimeter firewall',
            'Review web application firewall (WAF) logs for the same source',
            'Patch any identified vulnerability within 24 hours',
            'Increase logging verbosity on the affected service',
            'Check for any successful follow-on exploitation attempts',
        ]

    # Generic high/critical fallback
    if level >= LEVEL_CRITICAL:
        return [
            'Treat this as a CRITICAL PRIORITY — escalate to SOC management immediately',
            'Isolate the affected agent from the network pending investigation',
            'Preserve all logs and forensic artefacts before remediation',
            'Open an incident ticket and assign to a Tier-2 analyst now',
            'Notify CISO/management if data breach cannot be ruled out',
        ]

    return [
        'Review the alert details in the SentinelX ITDR dashboard',
        'Verify if the activity is expected and document your findings',
        'Isolate the affected agent if the activity cannot be explained',
        'Check for related alerts on the same agent in the last 48 hours',
        'Escalate to Tier-2 if you are unable to determine root cause within 30 minutes',
    ]


# ---------------------------------------------------------------------------
# Logo helper
# ---------------------------------------------------------------------------

def _load_logo_b64() -> str:
    try:
        logo_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'static', 'css', 'byteit-logo.jpg'
        )
        if os.path.exists(logo_path):
            with open(logo_path, 'rb') as f:
                return f'data:image/jpeg;base64,{base64.b64encode(f.read()).decode()}'
    except Exception:
        pass
    return ''
