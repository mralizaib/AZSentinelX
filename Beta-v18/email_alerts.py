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
    """Return the ByteIT logo as a base64 data URI, or empty string on failure."""
    try:
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'css', 'byteit-logo.jpg')
        with open(logo_path, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('utf-8')
        return f"data:image/jpeg;base64,{encoded}"
    except Exception as e:
        logger.warning(f"Could not load logo for email: {e}")
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

    def _build_html_email_body(self, total_alerts, alert_counts, severity_levels,
                                period_start, period_end, alerts_data,
                                include_fields, alert_check_interval,
                                ai_analysis_html=''):
        """
        Build a modern, professional HTML email body.

        Returns:
            str — complete HTML email string
        """
        logo_uri = _load_logo_base64()
        if logo_uri:
            logo_img_html = (
                f'<img src="{logo_uri}" width="60" height="60" alt="ByteIT" '
                f'style="border-radius:8px;background:#ffffff;padding:4px;display:block;">'
            )
        else:
            logo_img_html = (
                '<div style="width:60px;height:60px;background:rgba(255,255,255,0.2);'
                'border-radius:8px;display:flex;align-items:center;justify-content:center;'
                'color:#fff;font-weight:800;font-size:16px;">BI</div>'
            )

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

        # ── Threat intel section (email-safe conversion) ──────────────────────
        threat_intel_row = ''
        if ai_analysis_html.strip():
            threat_intel_row = f"""
        <!-- THREAT INTEL -->
        <tr>
          <td style="padding:0 32px 8px;">
            {ai_analysis_html}
          </td>
        </tr>"""

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
          <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 60%,#0057b8 100%);padding:28px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td width="68" valign="middle">
                  {logo_img_html}
                </td>
                <td style="padding-left:16px;" valign="middle">
                  <div style="color:rgba(255,255,255,0.65);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:5px;">ByteIT SentinalX &middot; Security Operations Center</div>
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

        {threat_intel_row}

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
                  <div style="color:#ffffff;font-weight:700;font-size:13px;letter-spacing:0.3px;">ByteIT SentinalX &nbsp;&middot;&nbsp; AZ Sentinel X</div>
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
        
        # Get the fields that should be used to identify unique alerts
        # Use fewer fields to prevent over-deduplication
        fields = {
            'rule_id': source.get('rule', {}).get('id', ''),
            'agent_ip': source.get('agent', {}).get('ip', ''),
            'agent_name': source.get('agent', {}).get('name', ''),
            'rule_level': source.get('rule', {}).get('level', ''),
            # Use rounded timestamp (to nearest minute) to group similar alerts
            'timestamp_minute': source.get('@timestamp', '')[:16] if source.get('@timestamp') else ''
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
            # Create message
            msg = MIMEMultipart()
            # Set sender name to "Wazuh" with the SMTP username as the email address
            msg['From'] = f"ByteIT SentinalX <{self.smtp_username}>"
            msg['To'] = recipient
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
                    
                    logger.info("📧 Sending message")
                    send_result = server.send_message(msg)
                    
                    if send_result:
                        error_msg = f"Some recipients failed: {send_result}"
                        logger.warning(f"📧 {error_msg}")
                        return False, error_msg
                    else:
                        logger.info("📧 Message sent to all recipients successfully")
                
                logger.info(f"✅ Alert email successfully sent to {recipient}")
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
        Check for new alerts and send emails to configured recipients
        """
        from models import AlertConfig
        
        try:
            # Get all enabled alert configurations
            configs = AlertConfig.query.filter_by(enabled=True).all()
            
            for config in configs:
                logger.info(f"Checking alerts for config: {config.name} (Recipient: {config.email_recipient})")
                self.send_severity_alert(config)
                
        except Exception as e:
            logger.error(f"Error in check_and_send_alerts: {str(e)}")

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
                subject = f"[TEST] ByteIT SentinalX — Alert System Connectivity Test"
                logo_uri = _load_logo_base64()
                logo_html = (f'<img src="{logo_uri}" width="56" height="56" alt="ByteIT" style="border-radius:8px;background:#fff;padding:3px;display:block;">'
                             if logo_uri else
                             '<div style="width:56px;height:56px;background:rgba(255,255,255,0.2);border-radius:8px;color:#fff;font-weight:800;font-size:15px;text-align:center;line-height:56px;">BI</div>')
                message = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>ByteIT SentinalX Test Alert</title></head>
<body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#eef2f7;">
  <tr><td align="center" style="padding:28px 16px;">
    <table role="presentation" width="580" cellspacing="0" cellpadding="0" border="0" style="max-width:580px;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(13,27,75,0.15);">
      <tr>
        <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 60%,#0057b8 100%);padding:26px 30px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr>
              <td width="64" valign="middle">{logo_html}</td>
              <td style="padding-left:16px;" valign="middle">
                <div style="color:rgba(255,255,255,0.65);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:4px;">ByteIT SentinalX &middot; Security Operations Center</div>
                <div style="color:#fff;font-size:20px;font-weight:700;line-height:1.2;">Alert System Test</div>
                <div style="color:rgba(255,255,255,0.7);font-size:12px;margin-top:4px;">{current_time_pkt.strftime('%A, %d %B %Y &mdash; %H:%M PKT')}</div>
              </td>
            </tr>
          </table>
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
              <td><div style="color:#fff;font-weight:700;font-size:12px;">ByteIT SentinalX &nbsp;&middot;&nbsp; AZ Sentinel X</div>
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

            # ── Threat intel block (patch-available items) ─────────────────────
            ai_analysis_html = ''
            try:
                import json as _json
                from models import ThreatIntelItem
                from datetime import timedelta as _td
                cutoff = datetime.datetime.utcnow() - _td(days=7)
                patch_items = (ThreatIntelItem.query
                               .filter(
                                   ThreatIntelItem.has_patch == True,
                                   ThreatIntelItem.ai_analyzed == True,
                                   ThreatIntelItem.published_at >= cutoff
                               )
                               .order_by(ThreatIntelItem.published_at.desc())
                               .limit(10)
                               .all())

                rows = []
                for ti in patch_items:
                    analysis = {}
                    if ti.ai_analysis:
                        try:
                            analysis = _json.loads(ti.ai_analysis)
                        except Exception:
                            pass
                    corr = ti.correlation
                    affected_count = corr.affected_count if corr else 0
                    env_action = (
                        (corr.env_recommended_action if corr else '')
                        or analysis.get('recommended_action', '')
                    )
                    if not env_action:
                        continue
                    sev_colors = {'critical': '#c0392b', 'high': '#e67e22',
                                  'medium': '#c8980a', 'low': '#27ae60'}
                    sev_color = sev_colors.get(ti.severity, '#6b7280')
                    affected_note = (
                        f"{affected_count} internal asset(s) affected"
                        if affected_count else "No inventory match — verify manually"
                    )
                    rows.append(f"""
                      <tr>
                        <td style="padding:8px 10px;border-bottom:1px solid #fde68a;font-weight:700;font-size:11px;color:{sev_color};white-space:nowrap;">{ti.severity.upper()}</td>
                        <td style="padding:8px 10px;border-bottom:1px solid #fde68a;font-size:11px;">{ti.title[:90]}</td>
                        <td style="padding:8px 10px;border-bottom:1px solid #fde68a;font-size:11px;color:#6b7280;">{affected_note}</td>
                        <td style="padding:8px 10px;border-bottom:1px solid #fde68a;font-size:11px;">{env_action}</td>
                      </tr>""")

                if rows:
                    table_rows = "\n".join(rows)
                    ai_analysis_html = f"""
                <div style="margin:0;padding:16px 18px;background:#fffbeb;border-left:5px solid #f59e0b;border-radius:6px;">
                  <div style="font-size:13px;font-weight:700;color:#92400e;margin-bottom:8px;">&#128994; Patch-Available Threat Intelligence (Last 7 Days)</div>
                  <div style="font-size:11px;color:#78350f;margin-bottom:10px;">The following correlated threats have confirmed patches available and require action:</div>
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;font-size:11px;">
                    <tr style="background:#fef3cd;">
                      <th style="padding:7px 10px;text-align:left;border-bottom:2px solid #fde68a;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:#92400e;">Severity</th>
                      <th style="padding:7px 10px;text-align:left;border-bottom:2px solid #fde68a;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:#92400e;">Threat</th>
                      <th style="padding:7px 10px;text-align:left;border-bottom:2px solid #fde68a;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:#92400e;">Exposure</th>
                      <th style="padding:7px 10px;text-align:left;border-bottom:2px solid #fde68a;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:#92400e;">Recommended Action</th>
                    </tr>
                    {table_rows}
                  </table>
                </div>"""
            except Exception as ti_err:
                logger.warning(f"Threat intel patch section for email skipped: {ti_err}")

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
                ai_analysis_html=ai_analysis_html,
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
