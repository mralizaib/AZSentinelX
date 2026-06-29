import os
import io
import csv
import base64
import logging
import smtplib
import hashlib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from config import Config
from opensearch_api import OpenSearchAPI
from report_generator import ReportGenerator
import datetime
from models import SentAlert, SystemConfig, db

logger = logging.getLogger(__name__)

def _load_logo_base64():
    """Logo embedding disabled — returns empty string to use text fallback."""
    return ""


class EmailAlerts:
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_username = Config.SMTP_USERNAME
        self.smtp_password = Config.SMTP_PASSWORD
        self.smtp_use_tls = Config.SMTP_USE_TLS
        self.opensearch = OpenSearchAPI()
        self.report_generator = ReportGenerator()

    # ──────────────────────────────────────────────────────────────────────────
    # Email body helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _build_csv_attachment(self, alerts_data, include_fields):
        """
        Build a CSV file (BytesIO) from alert results for use as an email attachment.

        Args:
            alerts_data: dict with 'results' list from OpenSearch
            include_fields: list of dot-notation field names to include as columns

        Returns:
            BytesIO object with CSV content
        """
        field_headers = {
            "@timestamp": "Timestamp (PKT)",
            "agent.ip": "Agent IP",
            "agent.labels.location.set": "Location",
            "agent.name": "Agent Name",
            "rule.description": "Description",
            "rule.id": "Rule ID",
            "rule.level": "Severity Level",
            "decoder.name": "Decoder",
            "full_log": "Full Log",
        }

        output = io.StringIO()
        writer = csv.writer(output)

        headers = [field_headers.get(f, f.split('.')[-1].capitalize()) for f in include_fields]
        writer.writerow(headers)

        for alert in alerts_data.get('results', []):
            source = alert.get('source', {})
            row = []
            for field in include_fields:
                value = "N/A"
                if field == "agent.labels.location.set":
                    value = source.get('agent', {}).get('labels', {}).get('location', {}).get('set', 'N/A')
                elif '.' in field:
                    parts = field.split('.')
                    current = source
                    for part in parts:
                        if isinstance(current, dict) and part in current:
                            current = current[part]
                        else:
                            current = "N/A"
                            break
                    if current not in ("N/A", None):
                        value = current
                else:
                    value = source.get(field, 'N/A')

                # Format timestamp to PKT
                if field == "@timestamp" and value != "N/A" and isinstance(value, str) and 'T' in value:
                    try:
                        utc_time = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                        pkt_time = utc_time + datetime.timedelta(hours=5)
                        value = pkt_time.strftime('%Y-%m-%d %H:%M:%S PKT')
                    except Exception:
                        pass

                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                row.append(str(value) if value is not None else 'N/A')
            writer.writerow(row)

        csv_bytes = io.BytesIO(output.getvalue().encode('utf-8'))
        return csv_bytes

    # ──────────────────────────────────────────────────────────────────────────
    # Threat Intelligence exposure summary (email section)
    # ──────────────────────────────────────────────────────────────────────────

    def _build_threat_intel_section(self) -> str:
        """
        Build an email-safe HTML block that summarises recent threat intelligence
        against the internal infrastructure using technology keyword matching.

        Items are classified as:
          ACTUAL EXPOSURE  — correlation confirmed OR affected agents found
                             (technology keywords matched known agents)
          ADVISORY         — threat from intel feeds but no keyword match in env

        Returns '' if no relevant items exist or on any error.
        """
        try:
            from models import ThreatIntelItem, ThreatIntelCorrelation
            from threat_intel_correlator import (
                WINDOWS_KEYWORDS, LINUX_KEYWORDS,
                NETWORK_KEYWORDS, WEBAPP_KEYWORDS,
            )
            import datetime as _dt

            cutoff = _dt.datetime.utcnow() - _dt.timedelta(days=7)
            items = (
                ThreatIntelItem.query
                .filter(ThreatIntelItem.fetched_at >= cutoff)
                .order_by(ThreatIntelItem.published_at.desc())
                .limit(60)
                .all()
            )
            if not items:
                return ''

            # ── Technology category labels ──────────────────────────────────
            TECH_LABELS = {
                'windows': ('Windows / Microsoft', WINDOWS_KEYWORDS),
                'linux':   ('Linux / Unix',        LINUX_KEYWORDS),
                'network': ('Network / Firewall',   NETWORK_KEYWORDS),
                'webapp':  ('Web Application',      WEBAPP_KEYWORDS),
            }

            def detect_tech(title, description):
                """Return a list of plain-English tech labels that match."""
                combined = (title + ' ' + (description or '')).lower()
                found = []
                for cat_key, (cat_label, kws) in TECH_LABELS.items():
                    if any(kw in combined for kw in kws):
                        found.append(cat_label)
                return found

            exposed_rows = []
            advisory_rows = []

            for item in items:
                analysis = {}
                if item.ai_analysis:
                    try:
                        analysis = json.loads(item.ai_analysis)
                    except Exception:
                        pass

                corr = item.correlation
                tech_labels = detect_tech(item.title, item.description)

                # Determine exposure classification
                is_exposure = bool(
                    corr and (corr.is_confirmed_present or corr.affected_count > 0)
                )

                # Skip items that have no tech keyword AND no correlation —
                # they are purely generic feed entries with no infrastructure angle.
                if not tech_labels and not is_exposure:
                    continue

                tech_str = ', '.join(tech_labels) if tech_labels else 'General'
                ai_summary = (
                    analysis.get('summary', '')
                    or (item.description[:180] if item.description else '')
                )
                if len(ai_summary) > 180:
                    ai_summary = ai_summary[:177] + '…'

                cve_str = ', '.join(item.get_cve_list()[:3]) if item.get_cve_list() else ''
                cve_html = (
                    f'<span style="font-size:9px;color:#6b7280;margin-left:6px;">{cve_str}</span>'
                    if cve_str else ''
                )
                patch_dot = (
                    '<span style="background:#059669;color:#fff;border-radius:3px;'
                    'padding:1px 5px;font-size:9px;margin-left:4px;">PATCH</span>'
                    if item.has_patch else ''
                )

                row_html = f"""
                <tr>
                  <td style="padding:9px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top;">
                    <div style="font-size:11px;font-weight:700;color:#111827;line-height:1.3;">
                      {item.title[:100]}{patch_dot}{cve_html}
                    </div>
                    <div style="font-size:10px;color:#6b7280;margin-top:3px;">{ai_summary}</div>
                  </td>
                  <td style="padding:9px 10px;border-bottom:1px solid #e5e7eb;white-space:nowrap;vertical-align:top;">
                    <span style="font-size:10px;color:#374151;">{tech_str}</span>
                  </td>
                </tr>"""

                if is_exposure:
                    agent_note = ''
                    if corr and corr.affected_count > 0:
                        agent_note = (
                            f' &mdash; {corr.affected_count} agent(s) matched'
                        )
                    confirmed_note = (
                        '<span style="background:#dc2626;color:#fff;border-radius:3px;'
                        'padding:1px 5px;font-size:9px;">CONFIRMED</span> '
                        if corr and corr.is_confirmed_present else
                        '<span style="background:#ea580c;color:#fff;border-radius:3px;'
                        'padding:1px 5px;font-size:9px;">POTENTIAL</span> '
                    )
                    row_html = f"""
                <tr>
                  <td style="padding:9px 10px;border-bottom:1px solid #fecaca;vertical-align:top;">
                    <div style="font-size:11px;font-weight:700;color:#111827;line-height:1.3;">
                      {confirmed_note}{item.title[:100]}{patch_dot}{cve_html}
                    </div>
                    <div style="font-size:10px;color:#6b7280;margin-top:3px;">{ai_summary}</div>
                    <div style="font-size:10px;color:#b91c1c;margin-top:2px;font-weight:600;">{agent_note}</div>
                  </td>
                  <td style="padding:9px 10px;border-bottom:1px solid #fecaca;white-space:nowrap;vertical-align:top;">
                    <span style="font-size:10px;color:#374151;">{tech_str}</span>
                  </td>
                </tr>"""
                    exposed_rows.append(row_html)
                else:
                    advisory_rows.append(row_html)

            # Cap to keep email manageable
            exposed_rows  = exposed_rows[:10]
            advisory_rows = advisory_rows[:8]

            if not exposed_rows and not advisory_rows:
                return ''

            # ── Exposed block ───────────────────────────────────────────────
            exposed_block = ''
            if exposed_rows:
                exposed_block = f"""
            <div style="font-size:11px;font-weight:700;color:#991b1b;margin-bottom:6px;
                        text-transform:uppercase;letter-spacing:0.4px;">
              &#128308; Actual Exposure &mdash; {len(exposed_rows)} threat(s) matched to your infrastructure
            </div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                   style="border-collapse:collapse;font-size:11px;border:1px solid #fecaca;
                          border-radius:6px;overflow:hidden;margin-bottom:12px;">
              <tr style="background:#fee2e2;">
                <th style="padding:7px 10px;text-align:left;font-size:9px;text-transform:uppercase;
                            letter-spacing:0.5px;color:#991b1b;">Threat / AI Summary</th>
                <th style="padding:7px 10px;text-align:left;font-size:9px;text-transform:uppercase;
                            letter-spacing:0.5px;color:#991b1b;white-space:nowrap;">Technology</th>
              </tr>
              {''.join(exposed_rows)}
            </table>"""

            # ── Advisory block ──────────────────────────────────────────────
            advisory_block = ''
            if advisory_rows:
                advisory_block = f"""
            <div style="font-size:11px;font-weight:700;color:#1d4ed8;margin-bottom:6px;
                        text-transform:uppercase;letter-spacing:0.4px;">
              &#128203; Advisory Only &mdash; {len(advisory_rows)} threat(s) from intel feeds (no environment match detected)
            </div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                   style="border-collapse:collapse;font-size:11px;border:1px solid #bfdbfe;
                          border-radius:6px;overflow:hidden;">
              <tr style="background:#eff6ff;">
                <th style="padding:7px 10px;text-align:left;font-size:9px;text-transform:uppercase;
                            letter-spacing:0.5px;color:#1d4ed8;">Threat / AI Summary</th>
                <th style="padding:7px 10px;text-align:left;font-size:9px;text-transform:uppercase;
                            letter-spacing:0.5px;color:#1d4ed8;white-space:nowrap;">Technology</th>
              </tr>
              {''.join(advisory_rows)}
            </table>"""

            return f"""
        <!-- ══ THREAT INTEL EXPOSURE SUMMARY ══ -->
        <tr>
          <td style="padding:20px 32px 24px;">
            <div style="font-size:12px;font-weight:700;color:#0d1b4b;border-left:4px solid #dc2626;
                        padding:5px 10px;margin-bottom:14px;background:#fff5f5;border-radius:0 4px 4px 0;
                        text-transform:uppercase;letter-spacing:0.5px;">
              Threat Intelligence &mdash; Infrastructure Assessment (Last 7 Days)
            </div>
            <div style="font-size:11px;color:#4b5563;margin-bottom:12px;">
              Threats are matched to your environment using technology keyword analysis
              (Windows, SonicWall, Linux, web applications, etc.) and correlated against
              your Wazuh agent inventory.
            </div>
            {exposed_block}
            {advisory_block}
          </td>
        </tr>"""

        except Exception as ti_err:
            logger.warning(f"Threat intel exposure section skipped: {ti_err}")
            return ''

    def _build_html_email_body(self, total_alerts, alert_counts, severity_levels,
                                period_start, period_end, alerts_data,
                                include_fields, alert_check_interval):
        """
        Build a modern, professional HTML email body.

        Returns:
            str — complete HTML email string
        """
        severity_levels_str = ', '.join(s.capitalize() for s in severity_levels)
        critical_count = alert_counts.get('critical', 0)
        high_count = alert_counts.get('high', 0)
        medium_count = alert_counts.get('medium', 0)
        low_count = alert_counts.get('low', 0)

        now_pkt = datetime.datetime.utcnow() + datetime.timedelta(hours=5)
        date_display = now_pkt.strftime('%A, %d %B %Y &mdash; %H:%M PKT')

        # ── Alert rows ────────────────────────────────────────────────────────
        row_html_parts = []
        results = alerts_data.get('results', [])
        for idx, alert in enumerate(results[:50]):
            source = alert.get('source', {})
            ts_raw = source.get('@timestamp', 'N/A')
            ts_display = ts_raw
            try:
                if 'T' in ts_raw:
                    utc_time = datetime.datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                    pkt_time = utc_time + datetime.timedelta(hours=5)
                    ts_display = pkt_time.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                pass

            agent_name = source.get('agent', {}).get('name', 'N/A')
            agent_ip = source.get('agent', {}).get('ip', '')
            rule_id = source.get('rule', {}).get('id', 'N/A')
            level = source.get('rule', {}).get('level', 0)
            description = source.get('rule', {}).get('description', 'N/A')
            if len(description) > 80:
                description = description[:77] + '...'

            if level >= 15:
                badge_bg, badge_fg, badge_border = '#fde8e8', '#c0392b', '#f5c6c6'
                sev_label = 'CRITICAL'
            elif level >= 12:
                badge_bg, badge_fg, badge_border = '#fef3cd', '#b45309', '#fde68a'
                sev_label = 'HIGH'
            elif level >= 7:
                badge_bg, badge_fg, badge_border = '#fffbeb', '#c8980a', '#fde68a'
                sev_label = 'MEDIUM'
            else:
                badge_bg, badge_fg, badge_border = '#d1fae5', '#065f46', '#a7f3d0'
                sev_label = 'LOW'

            row_bg = '#f9fafb' if idx % 2 == 0 else '#ffffff'
            row_html_parts.append(f"""
              <tr style="background:{row_bg};">
                <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-size:11px;white-space:nowrap;color:#374151;">{ts_display}</td>
                <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-size:11px;">
                  <strong style="color:#0d1b4b;">{agent_name}</strong>
                  {"<br><span style='font-size:10px;color:#9ca3af;'>" + agent_ip + "</span>" if agent_ip else ""}
                </td>
                <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-size:11px;font-family:monospace;color:#374151;">{rule_id}</td>
                <td style="padding:8px;border-bottom:1px solid #e5e7eb;">
                  <span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;background:{badge_bg};color:{badge_fg};border:1px solid {badge_border};">{sev_label}</span>
                </td>
                <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-size:11px;color:#374151;">{description}</td>
              </tr>""")

        alert_rows = ''.join(row_html_parts) if row_html_parts else (
            '<tr><td colspan="5" style="padding:20px;text-align:center;color:#9ca3af;font-size:12px;">'
            'No alert details available.</td></tr>'
        )
        shown_count = min(len(results), 50)

        # ── Assemble full template ─────────────────────────────────────────────
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Alert Notification &mdash; ByteIT SentinalX</title>
</head>
<body style="margin:0;padding:0;background-color:#eef2f7;font-family:Arial,Helvetica,sans-serif;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">

<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#eef2f7;">
  <tr>
    <td align="center" style="padding:28px 16px;">

      <!-- ─── EMAIL CARD ─── -->
      <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0"
             style="max-width:600px;width:100%;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(13,27,75,0.15);">

        <!-- ══ HEADER ══ -->
        <tr>
          <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 60%,#0057b8 100%);padding:24px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td valign="middle">
                  <div style="color:rgba(255,255,255,0.65);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:5px;">Security Operations Center &mdash; Alert Notification</div>
                  <div style="color:#ffffff;font-size:22px;font-weight:700;line-height:1.2;margin-bottom:5px;">Security Alert Notification</div>
                  <div style="color:rgba(255,255,255,0.7);font-size:12px;">{date_display}</div>
                </td>
                <td width="110" align="right" valign="middle" style="padding-left:12px;">
                  <div style="background:rgba(255,255,255,0.12);border-radius:8px;padding:10px 14px;text-align:center;">
                    <div style="color:rgba(255,255,255,0.65);font-size:9px;text-transform:uppercase;letter-spacing:1px;">Alerts</div>
                    <div style="color:#ffffff;font-size:34px;font-weight:800;line-height:1;">{total_alerts}</div>
                    <div style="color:rgba(255,255,255,0.65);font-size:9px;">New Detections</div>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ══ ACCENT BAR ══ -->
        <tr>
          <td height="5" style="background:linear-gradient(90deg,#00c9ff,#0057b8,#c0392b);font-size:0;line-height:0;">&nbsp;</td>
        </tr>

        <!-- ══ SUMMARY BANNER ══ -->
        <tr>
          <td style="padding:16px 32px;background-color:#fffbeb;border-bottom:2px solid #fde68a;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td>
                  <div style="font-size:14px;color:#92400e;font-weight:700;">&#9888; {total_alerts} new security alert(s) detected matching your configuration</div>
                  <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-top:8px;">
                    <tr>
                      <td style="font-size:12px;color:#b45309;padding-right:16px;"><strong>Levels:</strong> {severity_levels_str}</td>
                      <td style="font-size:12px;color:#b45309;"><strong>Period:</strong> {period_start} &rarr; {period_end} (PKT)</td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ══ SEVERITY CARDS ══ -->
        <tr>
          <td style="padding:24px 32px 20px;background:#f9fafb;border-bottom:1px solid #e5e7eb;">
            <div style="font-size:12px;font-weight:700;color:#0d1b4b;border-left:4px solid #0057b8;padding:5px 10px;margin-bottom:14px;background:#f0f4ff;border-radius:0 4px 4px 0;text-transform:uppercase;letter-spacing:0.5px;">Alert Summary by Severity</div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td width="23%" align="center" style="background:#ffffff;border-radius:8px;padding:14px 6px;border-top:4px solid #c0392b;box-shadow:0 1px 4px rgba(0,0,0,0.07);">
                  <div style="font-size:30px;font-weight:800;color:#c0392b;line-height:1;">{critical_count}</div>
                  <div style="font-size:10px;color:#9b2c2c;text-transform:uppercase;letter-spacing:1px;margin-top:5px;">Critical</div>
                </td>
                <td width="2%">&nbsp;</td>
                <td width="23%" align="center" style="background:#ffffff;border-radius:8px;padding:14px 6px;border-top:4px solid #e67e22;box-shadow:0 1px 4px rgba(0,0,0,0.07);">
                  <div style="font-size:30px;font-weight:800;color:#e67e22;line-height:1;">{high_count}</div>
                  <div style="font-size:10px;color:#9a3412;text-transform:uppercase;letter-spacing:1px;margin-top:5px;">High</div>
                </td>
                <td width="2%">&nbsp;</td>
                <td width="23%" align="center" style="background:#ffffff;border-radius:8px;padding:14px 6px;border-top:4px solid #f1c40f;box-shadow:0 1px 4px rgba(0,0,0,0.07);">
                  <div style="font-size:30px;font-weight:800;color:#c8980a;line-height:1;">{medium_count}</div>
                  <div style="font-size:10px;color:#78350f;text-transform:uppercase;letter-spacing:1px;margin-top:5px;">Medium</div>
                </td>
                <td width="2%">&nbsp;</td>
                <td width="23%" align="center" style="background:#ffffff;border-radius:8px;padding:14px 6px;border-top:4px solid #27ae60;box-shadow:0 1px 4px rgba(0,0,0,0.07);">
                  <div style="font-size:30px;font-weight:800;color:#27ae60;line-height:1;">{low_count}</div>
                  <div style="font-size:10px;color:#065f46;text-transform:uppercase;letter-spacing:1px;margin-top:5px;">Low</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ══ ALERT TABLE ══ -->
        <tr>
          <td style="padding:24px 32px 16px;">
            <div style="font-size:12px;font-weight:700;color:#0d1b4b;border-left:4px solid #0057b8;padding:5px 10px;margin-bottom:14px;background:#f0f4ff;border-radius:0 4px 4px 0;text-transform:uppercase;letter-spacing:0.5px;">Recent Security Alerts</div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;font-size:11px;">
              <tr style="background:#0d1b4b;">
                <th style="color:#fff;padding:9px 8px;text-align:left;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;">Timestamp (PKT)</th>
                <th style="color:#fff;padding:9px 8px;text-align:left;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:0.5px;">Agent</th>
                <th style="color:#fff;padding:9px 8px;text-align:left;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:0.5px;">Rule</th>
                <th style="color:#fff;padding:9px 8px;text-align:left;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:0.5px;">Severity</th>
                <th style="color:#fff;padding:9px 8px;text-align:left;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:0.5px;">Description</th>
              </tr>
              {alert_rows}
            </table>
            <div style="font-size:10px;color:#9ca3af;margin-top:8px;">
              Showing {shown_count} of {total_alerts} alert(s). &nbsp;Full details are in the attached PDF report.
            </div>
          </td>
        </tr>

        <!-- ══ ATTACHMENTS NOTE ══ -->
        <tr>
          <td style="padding:0 32px 28px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td style="background:#f0f4ff;border:1px solid #dbeafe;border-radius:8px;padding:14px 18px;">
                  <div style="font-size:12px;font-weight:700;color:#0d1b4b;margin-bottom:8px;">&#128206; Attachments Included</div>
                  <div style="font-size:11px;color:#374151;margin-bottom:4px;">&#128196; <strong>Security Alert Report (PDF)</strong> &mdash; Full formatted report with all alert details and raw logs</div>
                  <div style="font-size:11px;color:#374151;">&#128200; <strong>Alert Logs (CSV)</strong> &mdash; Raw alert data for SIEM import or further analysis</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ══ FOOTER ══ -->
        <tr>
          <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 100%);padding:18px 32px;border-radius:0 0 10px 10px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td valign="middle">
                  <div style="color:#ffffff;font-weight:700;font-size:13px;letter-spacing:0.3px;">ByteIT SentinalX</div>
                  <div style="color:rgba(255,255,255,0.6);font-size:10px;margin-top:4px;">Automated Security Alert &middot; Do not reply to this email</div>
                  <div style="color:rgba(255,255,255,0.6);font-size:10px;margin-top:2px;">IT Department &middot; itsupport@rebiz.com &middot; Created by Ali Zaib</div>
                </td>
                <td align="right" valign="middle" style="padding-left:12px;">
                  <span style="background:rgba(255,255,255,0.15);color:#ffffff;border-radius:10px;padding:5px 14px;font-size:10px;font-weight:700;letter-spacing:1px;white-space:nowrap;">CONFIDENTIAL</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table><!-- /card -->
    </td>
  </tr>
</table>

</body>
</html>"""
        return html
        
    def _generate_alert_identifier(self, alert_data):
        """
        Generate a unique identifier for an alert based on specified fields
        to prevent duplicate notifications
        
        Args:
            alert_data: The alert data from OpenSearch
            
        Returns:
            String hash representing the unique alert
        """
        # Extract key fields for deduplication
        source = alert_data.get('source', {})

        # If the event has an OpenSearch document ID, use it as the primary
        # unique key. This guarantees that each distinct FIM (or any) event
        # in OpenSearch maps to exactly one dedup record, regardless of how
        # many fields happen to match between two different events.
        event_id = alert_data.get('id', '')

        if event_id:
            fields = {'event_id': event_id}
        else:
            # Fallback for events without an _id (e.g., manually constructed
            # test payloads). Include the file path so two different files
            # changed at the same minute on the same agent are not collapsed.
            fields = {
                'rule_id': source.get('rule', {}).get('id', ''),
                'agent_ip': source.get('agent', {}).get('ip', ''),
                'agent_name': source.get('agent', {}).get('name', ''),
                'rule_level': source.get('rule', {}).get('level', ''),
                'syscheck_path': source.get('syscheck', {}).get('path', ''),
                'timestamp_minute': (
                    source.get('@timestamp', '')[:16]
                    if source.get('@timestamp') else ''
                ),
            }
        
        # Create a string representation and hash it
        identifier_str = json.dumps(fields, sort_keys=True)
        return hashlib.md5(identifier_str.encode()).hexdigest()
    
    def _is_alert_already_sent(self, alert_config_id, alert_identifier):
        """
        Check if an alert with this identifier has already been sent for this config
        
        Args:
            alert_config_id: ID of the alert configuration
            alert_identifier: Hash of the alert's unique identifiers
            
        Returns:
            Boolean indicating if the alert was already sent
        """
        # Get duplicate prevention window from system config or use 4 hours as default
        # Reduced from 24 hours to 4 hours to allow more alerts through
        duplicate_window = int(SystemConfig.get_value('alert_duplicate_window', '4'))
        cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=duplicate_window)
        
        # Query for existing alerts
        existing_alert = SentAlert.query.filter(
            SentAlert.alert_config_id == alert_config_id,
            SentAlert.alert_identifier == alert_identifier,
            SentAlert.timestamp >= cutoff_time
        ).first()
        
        return existing_alert is not None
        
    def _record_sent_alert(self, alert_config_id, alert_identifier):
        """
        Record that an alert has been sent to prevent duplicates
        
        Args:
            alert_config_id: ID of the alert configuration
            alert_identifier: Hash of the alert's unique identifiers
        """
        sent_alert = SentAlert(
            alert_config_id=alert_config_id,
            alert_identifier=alert_identifier
        )
        db.session.add(sent_alert)
        db.session.commit()
    
    def send_alert_email(self, recipient, subject, message, attachments=None):
        """
        Send alert email
        
        Args:
            recipient: Email recipient address
            subject: Email subject
            message: Email body (HTML)
            attachments: List of dicts with 'content' (BytesIO), 'filename', and 'mime_type'
            
        Returns:
            Tuple of (Boolean, String): (Success indicator, Error message if failed)
        """
        if not self.smtp_username or not self.smtp_password:
            error_msg = "SMTP credentials not configured"
            logger.error(error_msg)
            return False, error_msg
        
        try:
            # Support comma-separated multiple recipients
            recipient_list = [r.strip() for r in str(recipient).split(',') if r.strip()]
            if not recipient_list:
                return False, "No valid recipients"

            # Create message
            msg = MIMEMultipart()
            msg['From'] = f"ByteIT SentinalX <{self.smtp_username}>"
            msg['To'] = ', '.join(recipient_list)
            msg['Subject'] = subject
            
            # Attach HTML body
            msg.attach(MIMEText(message, 'html'))
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    try:
                        # Handle different content types
                        if hasattr(attachment['content'], 'read'):
                            # It's a file-like object (BytesIO)
                            content_data = attachment['content'].read()
                            # Reset file pointer for potential future reads
                            attachment['content'].seek(0)
                        elif isinstance(attachment['content'], bytes):
                            # It's already bytes
                            content_data = attachment['content']
                        else:
                            # Convert to bytes if it's a string
                            content_data = str(attachment['content']).encode('utf-8')
                        
                        part = MIMEApplication(
                            content_data,
                            Name=attachment['filename']
                        )
                        part['Content-Disposition'] = f'attachment; filename="{attachment["filename"]}"'
                        msg.attach(part)
                        
                    except Exception as attach_error:
                        logger.error(f"Error attaching file {attachment.get('filename', 'unknown')}: {str(attach_error)}")
                        continue
            
            # Connect to SMTP server and send email
            logger.info(f"📧 Connecting to SMTP server: {self.smtp_server}:{self.smtp_port}")
            
            try:
                # Use SMTP_SSL for port 465, regular SMTP for others
                if self.smtp_port == 465:
                    smtp_conn = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=30)
                else:
                    smtp_conn = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                
                with smtp_conn as server:
                    server.set_debuglevel(1)  # Enable SMTP debugging
                    
                    if self.smtp_port != 465 and self.smtp_use_tls:
                        logger.info("📧 Starting TLS connection")
                        server.starttls()
                    
                    logger.info(f"📧 Logging in with username: {self.smtp_username}")
                    server.login(self.smtp_username, self.smtp_password)
                    
                    logger.info(f"📧 Sending message to {len(recipient_list)} recipient(s): {', '.join(recipient_list)}")
                    send_result = server.sendmail(
                        self.smtp_username,
                        recipient_list,
                        msg.as_string()
                    )
                    
                    if send_result:
                        error_msg = f"Some recipients failed: {send_result}"
                        logger.warning(f"📧 {error_msg}")
                        return False, error_msg
                    else:
                        logger.info("📧 Message sent to all recipients successfully")
                
                logger.info(f"✅ Alert email successfully sent to {', '.join(recipient_list)}")
                return True, "Success"
            except smtplib.SMTPAuthenticationError as auth_error:
                error_msg = f"SMTP Authentication failed: {str(auth_error)}"
                logger.error(f"❌ {error_msg}")
                return False, error_msg
            except smtplib.SMTPRecipientsRefused as recip_error:
                error_msg = f"SMTP Recipients refused: {str(recip_error)}"
                logger.error(f"❌ {error_msg}")
                return False, error_msg
            except smtplib.SMTPServerDisconnected as disconnect_error:
                error_msg = f"SMTP Server disconnected: {str(disconnect_error)}"
                logger.error(f"❌ {error_msg}")
                return False, error_msg
            except Exception as smtp_error:
                error_msg = f"SMTP Error: {str(smtp_error)}"
                logger.error(f"❌ {error_msg}")
                return False, error_msg
        except Exception as e:
            error_msg = f"Failed to send alert email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def check_and_send_alerts(self):
        """
        Check for new alerts and send emails to configured recipients.
        Routes FIM configs to the dedicated FIM sender.
        """
        from models import AlertConfig

        try:
            configs = AlertConfig.query.filter_by(enabled=True).all()

            for config in configs:
                logger.info(f"Checking alerts for config: {config.name} (Recipient: {config.email_recipient})")
                if config.is_fim():
                    self.send_fim_alert(config)
                else:
                    self.send_severity_alert(config)

        except Exception as e:
            logger.error(f"Error in check_and_send_alerts: {str(e)}")

    # ──────────────────────────────────────────────────────────────────────────
    # FIM alert sender
    # ──────────────────────────────────────────────────────────────────────────

    def send_fim_alert(self, alert_config):
        """
        Fetch syscheck FIM events for the configured agents/paths and send a
        rich FIM email notification when new events are found.

        Args:
            alert_config: AlertConfig model instance with alert_type == 'fim'

        Returns:
            bool or (bool, str) — success indicator
        """
        try:
            agent_names = alert_config.get_fim_agent_names()
            paths       = alert_config.get_fim_paths()
            file_names  = alert_config.get_fim_file_names()
            file_exts   = alert_config.get_fim_file_extensions()
            recipient   = alert_config.email_recipient

            if not recipient:
                logger.error("FIM alert config has no recipient")
                return False, "No recipient"

            if not agent_names:
                logger.warning(f"FIM config '{alert_config.name}' has no agent names configured — skipping")
                return True, "No agent names configured"

            if not paths:
                logger.warning(f"FIM config '{alert_config.name}' has no paths configured — skipping")
                return True, "No paths configured"

            alert_check_interval = int(SystemConfig.get_value('alert_check_interval', '2'))
            now_utc  = datetime.datetime.utcnow()
            now_pkt  = now_utc + datetime.timedelta(hours=5)
            end_time  = now_utc.isoformat()
            start_time = (now_utc - datetime.timedelta(minutes=alert_check_interval)).isoformat()

            fim_data = self.opensearch.search_fim_events(
                start_time=start_time,
                end_time=end_time,
                agent_names=agent_names,
                paths=paths,
                file_names=file_names if file_names else None,
                file_extensions=file_exts if file_exts else None,
                limit=200
            )

            if 'error' in fim_data:
                logger.error(f"FIM search error for config '{alert_config.name}': {fim_data['error']}")
                return False, fim_data['error']

            total_found = len(fim_data.get('results', []))
            logger.info(f"FIM: found {total_found} event(s) for config '{alert_config.name}'")

            if total_found == 0:
                return True, "No FIM events to send"

            # Deduplication
            if hasattr(alert_config, 'id'):
                new_events = []
                for event in fim_data.get('results', []):
                    ident = self._generate_alert_identifier(event)
                    if not self._is_alert_already_sent(alert_config.id, ident):
                        new_events.append(event)

                if not new_events:
                    logger.info(f"FIM: all {total_found} event(s) already sent for config '{alert_config.name}'")
                    return True, "All FIM events already sent"

                for event in new_events:
                    self._record_sent_alert(alert_config.id, self._generate_alert_identifier(event))

                fim_data['results'] = new_events
                fim_data['total']   = len(new_events)

            # Build dynamic subject from the first event's action + path
            first_evt = fim_data['results'][0]
            _sc   = first_evt.get('source', {}).get('syscheck', {})
            _ag   = first_evt.get('source', {}).get('agent', {})
            _action_map = {'added': 'CREATED', 'modified': 'MODIFIED',
                           'deleted': 'DELETED', 'renamed': 'RENAMED'}
            _action    = _action_map.get(_sc.get('event', ''), 'CHANGED')
            _file_path = _sc.get('path', 'Unknown path')
            _agent     = _ag.get('name', agent_names[0] if agent_names else 'Unknown agent')
            _extra     = f" (+{len(fim_data['results']) - 1} more)" if len(fim_data['results']) > 1 else ""
            subject = (
                f"[ByteIT Sentinel X] FIM Alert \u2014 File {_action}: "
                f"{_file_path} on {_agent}{_extra}"
            )

            period_start_str = (now_pkt - datetime.timedelta(minutes=alert_check_interval)).strftime('%Y-%m-%d %H:%M')
            period_end_str   = now_pkt.strftime('%Y-%m-%d %H:%M')

            body = self._build_fim_html_email_body(
                config=alert_config,
                fim_data=fim_data,
                period_start=period_start_str,
                period_end=period_end_str,
                now_pkt=now_pkt,
            )

            # CSV attachment for FIM events
            attachments = []
            ts_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            try:
                csv_buf = self._build_fim_csv_attachment(fim_data)
                attachments.append({
                    'content': csv_buf,
                    'filename': f"fim_events_{ts_str}.csv",
                    'mime_type': 'text/csv'
                })
            except Exception as csv_err:
                logger.error(f"FIM CSV attachment error: {csv_err}")

            return self.send_alert_email(recipient, subject, body, attachments or None)

        except Exception as e:
            logger.error(f"send_fim_alert failed: {e}", exc_info=True)
            return False, str(e)

    def _build_fim_csv_attachment(self, fim_data):
        """Build a CSV BytesIO from FIM event results."""
        import io as _io
        import csv as _csv

        output = _io.StringIO()
        writer = _csv.writer(output)
        headers = [
            "Timestamp (PKT)", "Agent Name", "Agent IP", "Hostname",
            "File Path", "File Name", "Extension", "Action",
            "User", "Owner After", "MD5 After", "SHA1 After", "SHA256 After",
            "MD5 Before", "File Size", "Rule ID", "Rule Description", "Alert ID"
        ]
        writer.writerow(headers)

        for event in fim_data.get('results', []):
            src = event.get('source', {})
            sc  = src.get('syscheck', {})
            ag  = src.get('agent', {})
            rl  = src.get('rule', {})

            ts_raw = src.get('@timestamp', '')
            try:
                utc_t = datetime.datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                ts_display = (utc_t + datetime.timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S PKT')
            except Exception:
                ts_display = ts_raw

            full_path = sc.get('path', '')
            fname = full_path.split('/')[-1].split('\\')[-1] if full_path else ''
            ext   = ('.' + fname.rsplit('.', 1)[-1]) if '.' in fname else ''
            action_raw = sc.get('event', '')
            action_map = {'added': 'Created', 'modified': 'Modified', 'deleted': 'Deleted', 'renamed': 'Renamed'}
            action = action_map.get(action_raw, action_raw.capitalize() if action_raw else 'Unknown')

            user = (sc.get('audit', {}) or {}).get('user', {}) or {}
            if isinstance(user, dict):
                uname = user.get('name', src.get('syscheck', {}).get('uname_after', 'N/A'))
            else:
                uname = str(user)

            writer.writerow([
                ts_display,
                ag.get('name', 'N/A'),
                ag.get('ip', 'N/A'),
                src.get('hostname', ag.get('name', 'N/A')),
                full_path,
                fname,
                ext,
                action,
                uname,
                sc.get('uname_after', 'N/A'),
                sc.get('md5_after', 'N/A'),
                sc.get('sha1_after', 'N/A'),
                sc.get('sha256_after', 'N/A'),
                sc.get('md5_before', 'N/A'),
                sc.get('size_after', 'N/A'),
                rl.get('id', 'N/A'),
                rl.get('description', 'N/A'),
                event.get('id', 'N/A'),
            ])

        return _io.BytesIO(output.getvalue().encode('utf-8'))

    def _build_fim_html_email_body(self, config, fim_data, period_start, period_end, now_pkt):
        """
        Build a rich HTML email body for FIM alert notifications.
        Contains every field required by the FIM alert specification.
        """
        date_display = now_pkt.strftime('%A, %d %B %Y &mdash; %H:%M PKT')
        total_events = len(fim_data.get('results', []))

        # ── per-event cards ──────────────────────────────────────────────────
        event_cards_html = []
        action_icon = {'added': '&#43;', 'modified': '&#9998;', 'deleted': '&#128465;', 'renamed': '&#8614;'}
        action_color = {'added': '#059669', 'modified': '#d97706', 'deleted': '#dc2626', 'renamed': '#7c3aed'}
        action_label = {'added': 'CREATED', 'modified': 'MODIFIED', 'deleted': 'DELETED', 'renamed': 'RENAMED'}

        for idx, event in enumerate(fim_data.get('results', [])[:50]):
            src = event.get('source', {})
            sc  = src.get('syscheck', {})
            ag  = src.get('agent', {})
            rl  = src.get('rule', {})
            audit = (sc.get('audit') or {})
            audit_user = (audit.get('user') or {}) if isinstance(audit, dict) else {}

            ts_raw = src.get('@timestamp', '')
            try:
                utc_t = datetime.datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                ts_display = (utc_t + datetime.timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S PKT')
            except Exception:
                ts_display = ts_raw

            full_path  = sc.get('path', 'N/A')
            fname      = full_path.split('/')[-1].split('\\')[-1] if full_path and full_path != 'N/A' else 'N/A'
            ext        = ('.' + fname.rsplit('.', 1)[-1]) if fname != 'N/A' and '.' in fname else 'N/A'

            action_raw = sc.get('event', '')
            col    = action_color.get(action_raw, '#374151')
            icon   = action_icon.get(action_raw, '&#9679;')
            alabel = action_label.get(action_raw, (action_raw.upper() if action_raw else 'UNKNOWN'))

            uname = (audit_user.get('name') if isinstance(audit_user, dict) else None) or sc.get('uname_after') or 'N/A'
            usid  = (audit_user.get('id')   if isinstance(audit_user, dict) else None) or 'N/A'

            win_perm = sc.get('win_perm_after') or {}
            perm_name = (win_perm.get('name') if isinstance(win_perm, dict) else None) or 'N/A'

            hostname  = src.get('hostname') or ag.get('name', 'N/A')
            agent_grp = ag.get('group', 'N/A')
            agent_os  = (src.get('agent', {}).get('os') or src.get('os') or {})
            os_info   = agent_os.get('name', 'N/A') if isinstance(agent_os, dict) else str(agent_os)

            row_bg = '#f9fafb' if idx % 2 == 0 else '#ffffff'

            def _td(label, val, mono=False):
                mono_style = "font-family:monospace;font-size:10px;" if mono else "font-size:11px;"
                return (
                    f'<tr style="background:{row_bg};">'
                    f'<td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font-size:10px;'
                    f'font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:0.4px;'
                    f'white-space:nowrap;width:35%;">{label}</td>'
                    f'<td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;{mono_style}'
                    f'color:#111827;word-break:break-all;">{val if val not in (None, "", {}) else "N/A"}</td>'
                    f'</tr>'
                )

            card = f"""
            <!-- EVENT {idx+1} -->
            <tr>
              <td style="padding:20px 32px {'4px' if idx < total_events - 1 else '20px'} 32px;">
                <!-- Event header -->
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                       style="background:{col}12;border:1.5px solid {col}40;border-radius:8px;overflow:hidden;margin-bottom:4px;">
                  <tr>
                    <td style="background:{col};padding:10px 16px;">
                      <span style="font-size:18px;color:#fff;">{icon}</span>
                      <span style="color:#fff;font-size:13px;font-weight:800;letter-spacing:0.5px;margin-left:8px;">
                        {alabel} — Alert #{idx+1}
                      </span>
                      <span style="float:right;color:rgba(255,255,255,0.8);font-size:11px;">{ts_display}</span>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:0;">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                             style="border-collapse:collapse;">

                        <!-- SYSTEM INFORMATION -->
                        <tr style="background:#f0f4ff;">
                          <td colspan="2" style="padding:7px 10px;font-size:10px;font-weight:800;
                              color:#0d1b4b;text-transform:uppercase;letter-spacing:0.6px;
                              border-bottom:1px solid #e5e7eb;">
                            &#128187; System Information
                          </td>
                        </tr>
                        {_td("Agent Name", ag.get("name", "N/A"))}
                        {_td("Agent IP", ag.get("ip", "N/A"))}
                        {_td("Hostname", hostname)}
                        {_td("Agent Group", agent_grp)}
                        {_td("Operating System", os_info)}
                        {_td("Username (Change)", uname)}
                        {_td("Owner After Change", sc.get("uname_after", "N/A"))}
                        {_td("Permissions After", perm_name)}

                        <!-- FILE INFORMATION -->
                        <tr style="background:#f0fdf4;">
                          <td colspan="2" style="padding:7px 10px;font-size:10px;font-weight:800;
                              color:#065f46;text-transform:uppercase;letter-spacing:0.6px;
                              border-bottom:1px solid #e5e7eb;border-top:1px solid #e5e7eb;">
                            &#128196; File Information
                          </td>
                        </tr>
                        {_td("Full File Path", full_path, mono=True)}
                        {_td("File Name", fname)}
                        {_td("Extension / Type", ext)}
                        {_td("File Size (bytes)", sc.get("size_after", "N/A"))}

                        <!-- ACTION INFORMATION -->
                        <tr style="background:#fffbeb;">
                          <td colspan="2" style="padding:7px 10px;font-size:10px;font-weight:800;
                              color:#92400e;text-transform:uppercase;letter-spacing:0.6px;
                              border-bottom:1px solid #e5e7eb;border-top:1px solid #e5e7eb;">
                            &#9889; Action Information
                          </td>
                        </tr>
                        {_td("Action Performed", alabel)}
                        {_td("Date &amp; Time", ts_display)}
                        {_td("File Creation Date", sc.get("mtime", sc.get("ctime", "N/A")))}
                        {_td("Last Modified Date", sc.get("mtime", "N/A"))}

                        <!-- INTEGRITY INFORMATION -->
                        <tr style="background:#fdf4ff;">
                          <td colspan="2" style="padding:7px 10px;font-size:10px;font-weight:800;
                              color:#6b21a8;text-transform:uppercase;letter-spacing:0.6px;
                              border-bottom:1px solid #e5e7eb;border-top:1px solid #e5e7eb;">
                            &#128274; Integrity Information
                          </td>
                        </tr>
                        {_td("MD5 (Current)", sc.get("md5_after", "N/A"), mono=True)}
                        {_td("SHA1 (Current)", sc.get("sha1_after", "N/A"), mono=True)}
                        {_td("SHA256 (Current)", sc.get("sha256_after", "N/A"), mono=True)}
                        {_td("Previous MD5", sc.get("md5_before", "N/A"), mono=True)}
                        {_td("Previous SHA1", sc.get("sha1_before", "N/A"), mono=True)}

                        <!-- USER INFORMATION -->
                        <tr style="background:#fff1f2;">
                          <td colspan="2" style="padding:7px 10px;font-size:10px;font-weight:800;
                              color:#9f1239;text-transform:uppercase;letter-spacing:0.6px;
                              border-bottom:1px solid #e5e7eb;border-top:1px solid #e5e7eb;">
                            &#128100; User Information
                          </td>
                        </tr>
                        {_td("Username", uname)}
                        {_td("User SID", usid)}
                        {_td("Audit Info", str(audit) if audit else "N/A")}

                        <!-- ALERT INFORMATION -->
                        <tr style="background:#f1f5f9;">
                          <td colspan="2" style="padding:7px 10px;font-size:10px;font-weight:800;
                              color:#1e293b;text-transform:uppercase;letter-spacing:0.6px;
                              border-bottom:1px solid #e5e7eb;border-top:1px solid #e5e7eb;">
                            &#128276; Alert Information
                          </td>
                        </tr>
                        {_td("Alert Name", "Critical File Change Detected \u2013 Immediate Attention Required")}
                        {_td("Alert Severity", str(rl.get("level", "N/A")))}
                        {_td("Rule ID", str(rl.get("id", "N/A")))}
                        {_td("Rule Description", rl.get("description", "N/A"))}
                        {_td("Event Timestamp", ts_display)}
                        {_td("Alert ID", event.get("id", "N/A"), mono=True)}

                      </table>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>"""
            event_cards_html.append(card)

        cards_joined = '\n'.join(event_cards_html)

        agent_names_str = ', '.join(config.get_fim_agent_names()[:5])
        paths_str = ', '.join(config.get_fim_paths()[:3])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FIM Alert – Critical File Change Detected</title>
</head>
<body style="margin:0;padding:0;background-color:#eef2f7;font-family:Arial,Helvetica,sans-serif;">

<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#eef2f7;">
  <tr>
    <td align="center" style="padding:28px 16px;">

      <table role="presentation" width="660" cellspacing="0" cellpadding="0" border="0"
             style="max-width:660px;width:100%;background:#ffffff;border-radius:10px;
                    overflow:hidden;box-shadow:0 4px 20px rgba(13,27,75,0.15);">

        <!-- HEADER -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e0a3c 0%,#7c3aed 60%,#4f46e5 100%);padding:24px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td valign="middle">
                  <div style="color:rgba(255,255,255,0.65);font-size:10px;text-transform:uppercase;
                              letter-spacing:2px;margin-bottom:5px;">
                    File Integrity Monitor &mdash; Alert Notification
                  </div>
                  <div style="color:#ffffff;font-size:20px;font-weight:700;line-height:1.2;margin-bottom:5px;">
                    Critical File Change Detected
                  </div>
                  <div style="color:rgba(255,255,255,0.7);font-size:12px;">{date_display}</div>
                </td>
                <td width="120" align="right" valign="middle" style="padding-left:12px;">
                  <div style="background:rgba(255,255,255,0.12);border-radius:8px;
                              padding:10px 14px;text-align:center;">
                    <div style="color:rgba(255,255,255,0.65);font-size:9px;text-transform:uppercase;
                                letter-spacing:1px;">FIM Events</div>
                    <div style="color:#ffffff;font-size:34px;font-weight:800;line-height:1;">
                      {total_events}
                    </div>
                    <div style="color:rgba(255,255,255,0.65);font-size:9px;">Immediate Attention</div>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ACCENT BAR -->
        <tr>
          <td height="5" style="background:linear-gradient(90deg,#7c3aed,#dc2626,#d97706);
              font-size:0;line-height:0;">&nbsp;</td>
        </tr>

        <!-- SUMMARY BANNER -->
        <tr>
          <td style="padding:16px 32px;background:#fdf4ff;border-bottom:2px solid #e9d5ff;">
            <div style="font-size:14px;color:#6b21a8;font-weight:700;">
              &#128680; {total_events} File Integrity Event(s) Detected &mdash; Immediate Attention Required
            </div>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-top:8px;">
              <tr>
                <td style="font-size:11px;color:#7c3aed;padding-right:16px;">
                  <strong>Agents:</strong> {agent_names_str}
                </td>
                <td style="font-size:11px;color:#7c3aed;padding-right:16px;">
                  <strong>Paths:</strong> {paths_str}
                </td>
                <td style="font-size:11px;color:#7c3aed;">
                  <strong>Period:</strong> {period_start} &rarr; {period_end} (PKT)
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ALERT NOTICE -->
        <tr>
          <td style="padding:16px 32px 4px;">
            <div style="background:#fff5f5;border:1px solid #fecaca;border-radius:6px;
                        padding:12px 16px;font-size:12px;color:#7f1d1d;line-height:1.5;">
              <strong>&#9888; Security Notice:</strong> The following file system events were detected
              on monitored agents and paths. This alert is generated per your FIM configuration.
              Please review each event and take appropriate action if the changes were not authorized.
            </div>
          </td>
        </tr>

        <!-- EVENT CARDS -->
        {cards_joined}

        <!-- FOOTER -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e0a3c 0%,#4f46e5 100%);
              padding:16px 32px;border-radius:0 0 10px 10px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td>
                  <div style="color:#fff;font-weight:700;font-size:12px;">ByteIT SentinalX — FIM Monitor</div>
                  <div style="color:rgba(255,255,255,0.55);font-size:10px;margin-top:3px;">
                    Automated file integrity notification &middot; IT Department &middot; itsupport@rebiz.com
                  </div>
                </td>
                <td align="right">
                  <span style="background:rgba(255,255,255,0.15);color:#fff;border-radius:10px;
                               padding:4px 12px;font-size:10px;font-weight:700;">CONFIDENTIAL</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
</body>
</html>"""
        return html

    def send_severity_alert(self, alert_config, alerts_data=None):
        """
        Send an alert email based on severity configuration
        
        Args:
            alert_config: AlertConfig object
            alerts_data: Optional pre-fetched alerts data
            
        Returns:
            Tuple of (Boolean, String): (Success indicator, Error message if failed)
        """
        try:
            # Get severity levels from config
            if hasattr(alert_config, 'get_alert_levels'):
                severity_levels = alert_config.get_alert_levels()
            else:
                severity_levels = alert_config.get('alert_levels', ['critical', 'high'])
            
            recipient = alert_config.email_recipient if hasattr(alert_config, 'email_recipient') else alert_config.get('email_recipient')
            
            if not recipient:
                error_msg = "No recipient specified for alert"
                logger.error(error_msg)
                return False, error_msg
            
            # Set time range for alerts
            # Get the alert check interval from system config or use 2 minutes as default
            alert_check_interval = int(SystemConfig.get_value('alert_check_interval', '2'))
            current_time_utc = datetime.datetime.utcnow()
            current_time_pkt = current_time_utc + datetime.timedelta(hours=5)  # Pakistan Standard Time
            end_time = current_time_utc.isoformat()
            start_time = (current_time_utc - datetime.timedelta(minutes=alert_check_interval)).isoformat()
            
            # If alerts data not provided, fetch it
            if not alerts_data:
                alerts_data = self.opensearch.search_alerts(
                    severity_levels=severity_levels,
                    start_time=start_time,
                    end_time=end_time,
                    limit=100
                )
            
            if 'error' in alerts_data:
                error_msg = f"Error fetching alerts for email: {alerts_data['error']}"
                logger.error(error_msg)
                return False, error_msg
            
            # Check if there are any alerts to send
            total_alerts_found = len(alerts_data.get('results', []))
            logger.info(f"Found {total_alerts_found} alerts for levels: {', '.join(severity_levels)}")
            
            if total_alerts_found == 0 and not alerts_data.get('manual_test', False):
                logger.info(f"No alerts to send for levels: {', '.join(severity_levels)}")
                return True, "No alerts to send"
                
            # If this is a manual test with no alerts, create a test message
            if alerts_data.get('manual_test', False) and not alerts_data.get('results', []):
                logger.info("Creating test alert email for manual trigger")
                subject = f"[TEST] Alert System Connectivity Test — {alert_config.name if hasattr(alert_config, 'name') else 'Alert Config'}"
                message = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Alert System Test</title></head>
<body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#eef2f7;">
  <tr><td align="center" style="padding:28px 16px;">
    <table role="presentation" width="580" cellspacing="0" cellpadding="0" border="0" style="max-width:580px;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(13,27,75,0.15);">
      <tr>
        <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 60%,#0057b8 100%);padding:22px 30px;">
          <div style="color:rgba(255,255,255,0.65);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:4px;">Security Operations Center &mdash; Alert Notification</div>
          <div style="color:#fff;font-size:20px;font-weight:700;line-height:1.2;">Alert System Test</div>
          <div style="color:rgba(255,255,255,0.7);font-size:12px;margin-top:4px;">{current_time_pkt.strftime('%A, %d %B %Y &mdash; %H:%M PKT')}</div>
        </td>
      </tr>
      <tr><td height="5" style="background:linear-gradient(90deg,#00c9ff,#0057b8,#27ae60);font-size:0;line-height:0;">&nbsp;</td></tr>
      <tr>
        <td style="padding:28px 30px;">
          <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:18px 20px;margin-bottom:20px;">
            <div style="font-size:15px;font-weight:700;color:#065f46;margin-bottom:8px;">&#10003; Email delivery confirmed</div>
            <div style="font-size:13px;color:#374151;">This is a test notification triggered manually from the Scheduler Management interface. Your alert notification system is working correctly.</div>
          </div>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;font-size:12px;">
            <tr style="background:#f9fafb;">
              <td style="padding:9px 12px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;text-transform:uppercase;font-size:10px;letter-spacing:0.5px;width:40%;">Configuration</td>
              <td style="padding:9px 12px;border:1px solid #e5e7eb;font-weight:600;color:#0d1b4b;width:60%;">Value</td>
            </tr>
            <tr>
              <td style="padding:9px 12px;border:1px solid #e5e7eb;color:#6b7280;font-size:11px;">Alert Levels</td>
              <td style="padding:9px 12px;border:1px solid #e5e7eb;font-weight:600;">{', '.join(s.capitalize() for s in severity_levels)}</td>
            </tr>
            <tr style="background:#f9fafb;">
              <td style="padding:9px 12px;border:1px solid #e5e7eb;color:#6b7280;font-size:11px;">Check Interval</td>
              <td style="padding:9px 12px;border:1px solid #e5e7eb;font-weight:600;">{alert_check_interval} minutes</td>
            </tr>
            <tr>
              <td style="padding:9px 12px;border:1px solid #e5e7eb;color:#6b7280;font-size:11px;">Search Window</td>
              <td style="padding:9px 12px;border:1px solid #e5e7eb;font-weight:600;">{(current_time_pkt - datetime.timedelta(minutes=alert_check_interval)).strftime('%Y-%m-%d %H:%M')} &rarr; {current_time_pkt.strftime('%Y-%m-%d %H:%M')} PKT</td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 100%);padding:16px 30px;border-radius:0 0 10px 10px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr>
              <td><div style="color:#fff;font-weight:700;font-size:12px;">ByteIT SentinalX</div>
              <div style="color:rgba(255,255,255,0.55);font-size:10px;margin-top:3px;">Automated notification &middot; IT Department &middot; itsupport@rebiz.com</div></td>
              <td align="right"><span style="background:rgba(255,255,255,0.15);color:#fff;border-radius:10px;padding:4px 12px;font-size:10px;font-weight:700;">CONFIDENTIAL</span></td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body>
</html>"""
                return self.send_alert_email(recipient, subject, message)
                
            # Filter out alerts that have already been sent
            if hasattr(alert_config, 'id'):
                new_alerts = []
                duplicate_count = 0
                
                for alert in alerts_data.get('results', []):
                    alert_identifier = self._generate_alert_identifier(alert)
                    
                    if not self._is_alert_already_sent(alert_config.id, alert_identifier):
                        new_alerts.append(alert)
                        logger.debug(f"New alert found: {alert_identifier[:10]}...")
                    else:
                        duplicate_count += 1
                        logger.debug(f"Duplicate alert skipped: {alert_identifier[:10]}...")
                
                logger.info(f"Alert deduplication - Total: {len(alerts_data.get('results', []))}, New: {len(new_alerts)}, Duplicates: {duplicate_count}")
                
                # If no new alerts and this isn't a manual test, return success
                if not new_alerts and not alerts_data.get('manual_test', False):
                    logger.info(f"All {len(alerts_data.get('results', []))} alerts have already been sent for config {alert_config.id}")
                    return True  # Return success as all alerts were already sent
                
                # Record new alerts as sent AFTER we know we'll actually send them
                for alert in new_alerts:
                    alert_identifier = self._generate_alert_identifier(alert)
                    self._record_sent_alert(alert_config.id, alert_identifier)
                
                # Replace the results with only new alerts
                alerts_data['results'] = new_alerts
                alerts_data['total'] = len(new_alerts)
            
            # Get alert count by severity
            alert_counts = self.opensearch.get_alert_count_by_severity(
                start_time=start_time,
                end_time=end_time
            )
            
            # Pass the actual alerts data to ensure report contains current alerts
            try:
                # Get the include_fields if available
                include_fields = []
                if hasattr(alert_config, 'get_include_fields') and callable(getattr(alert_config, 'get_include_fields')):
                    include_fields = alert_config.get_include_fields()
                else:
                    include_fields = ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"]

                report_config_for_gen = {
                    'severity_levels': severity_levels,
                    'include_fields': include_fields
                }

                report = self.report_generator.generate_report(
                    report_config_for_gen, 
                    start_time, 
                    end_time, 
                    format='pdf',
                    alerts_data=alerts_data  # Pass the actual alerts data
                )
                
                if report:
                    logger.info(f"Successfully generated report attachment with {len(alerts_data.get('results', []))} alerts")
                else:
                    logger.error("Report generator returned None")
                    
            except Exception as report_error:
                logger.error(f"Failed to generate report for email attachment: {str(report_error)}")
                report = None
            
            # ── Email subject ──────────────────────────────────────────────────
            total_alerts = alerts_data.get('total', 0)
            highest = ('Critical' if alert_counts.get('critical', 0) else
                       'High'     if alert_counts.get('high',     0) else
                       'Medium'   if alert_counts.get('medium',   0) else 'Low')
            subject = f"[{highest}] ByteIT SentinalX — {total_alerts} Security Alert(s) Detected"

            # Threat intel section removed — email contains only fresh alert records

            # ── Build formatted HTML email body ────────────────────────────────
            period_start_str = (current_time_pkt - datetime.timedelta(minutes=alert_check_interval)).strftime('%Y-%m-%d %H:%M')
            period_end_str   = current_time_pkt.strftime('%Y-%m-%d %H:%M')

            body = self._build_html_email_body(
                total_alerts=total_alerts,
                alert_counts=alert_counts,
                severity_levels=severity_levels,
                period_start=period_start_str,
                period_end=period_end_str,
                alerts_data=alerts_data,
                include_fields=include_fields,
                alert_check_interval=alert_check_interval,
            )

            # ── Build attachments (PDF report + CSV logs) ──────────────────────
            attachments = []
            ts_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

            # 1. PDF report
            if report:
                try:
                    if hasattr(report, 'read'):
                        attachments.append({
                            'content': report,
                            'filename': f"security_alert_report_{ts_str}.pdf",
                            'mime_type': 'application/pdf'
                        })
                    elif isinstance(report, str):
                        attachments.append({
                            'content': io.BytesIO(report.encode('utf-8')),
                            'filename': f"security_alert_report_{ts_str}.html",
                            'mime_type': 'text/html'
                        })
                    else:
                        logger.warning("Report format not recognised, skipping PDF attachment")
                except Exception as attach_error:
                    logger.error(f"Error preparing PDF attachment: {str(attach_error)}")

            # 2. CSV log attachment
            try:
                csv_content = self._build_csv_attachment(alerts_data, include_fields)
                attachments.append({
                    'content': csv_content,
                    'filename': f"alert_logs_{ts_str}.csv",
                    'mime_type': 'text/csv'
                })
                logger.info(f"CSV attachment prepared with {len(alerts_data.get('results', []))} alert rows")
            except Exception as csv_error:
                logger.error(f"Error preparing CSV attachment: {str(csv_error)}")

            if not attachments:
                attachments = None
            
            # Send the email
            logger.info(f"📧 Attempting to send alert email to {recipient}")
            logger.info(f"📧 Subject: {subject}")
            logger.info(f"📧 Body length: {len(body)} characters")
            
            try:
                result = self.send_alert_email(recipient, subject, body, attachments)
                if result:
                    logger.info(f"✅ Alert email successfully sent to {recipient}")
                else:
                    logger.error(f"❌ Alert email failed to send to {recipient}")
                return result
            except Exception as e:
                logger.error(f"❌ Exception while sending alert email to {recipient}: {str(e)}")
                return False
        
        except Exception as e:
            logger.error(f"Error sending severity alert: {str(e)}")
            return False
