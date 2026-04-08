"""
Remediation Policy Engine
=========================
Evaluates active RemediationPolicy records against new ITDRDetection objects
and executes the configured actions (email alert, webhook POST).
"""

import json
import logging
import requests
from datetime import datetime
from email_alerts import EmailAlerts

logger = logging.getLogger(__name__)

SEV_RANK = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}


def apply_policies(app, detections: list):
    """
    For each new detection, check all enabled policies and fire matching actions.
    Called by itdr_engine after each scan cycle.
    """
    with app.app_context():
        from models import db, RemediationPolicy, RemediationAction

        policies = RemediationPolicy.query.filter_by(enabled=True).all()
        if not policies:
            return

        for det in detections:
            for policy in policies:
                if _matches(policy, det):
                    _execute(app, policy, det)


def _matches(policy, det) -> bool:
    """Return True if the detection satisfies the policy trigger conditions."""
    # Category filter (empty = any)
    cats = policy.get_trigger_categories()
    if cats and det.category not in cats:
        return False

    # Severity filter (empty = any)
    sevs = policy.get_trigger_severities()
    if sevs and det.severity not in sevs:
        return False

    # Event count threshold
    if det.event_count < (policy.trigger_min_event_count or 1):
        return False

    return True


def _execute(app, policy, det):
    """Fire the policy action and log the result."""
    from models import db, RemediationAction

    action_log = RemediationAction(
        policy_id=policy.id,
        detection_id=det.id,
        incident_id=det.incident_id,
        action_type=policy.action_type,
        status='pending',
        executed_at=datetime.utcnow(),
    )
    db.session.add(action_log)
    db.session.flush()

    try:
        if policy.action_type == 'email':
            _send_email(policy, det)
            action_log.status = 'success'
            action_log.result_message = f'Alert email sent to {policy.action_email}'
            det.alert_sent = True

        elif policy.action_type == 'webhook':
            resp_text = _post_webhook(policy, det)
            action_log.status = 'success'
            action_log.result_message = f'Webhook delivered: {resp_text[:200]}'

        elif policy.action_type == 'escalate':
            _escalate_incident(app, det)
            action_log.status = 'success'
            action_log.result_message = 'Incident escalated to Critical'

        else:
            action_log.status = 'failed'
            action_log.result_message = f'Unknown action type: {policy.action_type}'

    except Exception as exc:
        action_log.status = 'failed'
        action_log.result_message = str(exc)[:500]
        logger.error(f'Remediation action failed (policy {policy.id}): {exc}')

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f'Failed to save remediation action log: {exc}')


def _send_email(policy, det):
    """Send an ITDR alert email using the existing EmailAlerts infrastructure."""
    from config import Config
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    recipient = policy.action_email
    if not recipient:
        raise ValueError('No email recipient configured in policy')

    sev_color = {
        'critical': '#dc2626', 'high': '#d97706',
        'medium':   '#2563eb', 'low':  '#16a34a',
    }.get(det.severity, '#6b7280')

    sev_badge = det.severity.upper()
    agents_str = ', '.join(det.get_target_agents()) or 'N/A'
    src_ip_str = det.source_ip or 'N/A'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>ITDR Alert</title></head>
<body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#eef2f7;">
  <tr><td align="center" style="padding:28px 16px;">
    <table role="presentation" width="580" cellspacing="0" cellpadding="0" border="0"
           style="max-width:580px;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(13,27,75,0.15);">
      <tr>
        <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 60%,{sev_color} 100%);padding:26px 30px;">
          <div style="color:rgba(255,255,255,.65);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:4px;">
            ByteIT SentinelX &middot; ITDR / XDR Alert
          </div>
          <div style="color:#fff;font-size:20px;font-weight:700;">{det.rule_name}</div>
          <div style="margin-top:8px;">
            <span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:700;">{sev_badge}</span>
            &nbsp;
            <span style="color:rgba(255,255,255,.75);font-size:12px;">{det.category.replace('_',' ').title()}</span>
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:28px 30px;">
          <p style="color:#374151;font-size:14px;margin:0 0 20px;">
            A new threat detection has been triggered by your automated policy
            <strong>&ldquo;{policy.name}&rdquo;</strong>.
          </p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                 style="border-collapse:collapse;font-size:13px;">
            <tr style="background:#f9fafb;">
              <td style="padding:9px 14px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;width:40%;">Detection ID</td>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;color:#111827;">{det.detection_id[:16]}...</td>
            </tr>
            <tr>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;">Rule</td>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;color:#111827;">{det.rule_id} — {det.rule_name}</td>
            </tr>
            <tr style="background:#f9fafb;">
              <td style="padding:9px 14px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;">Source IP</td>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;color:#111827;">{src_ip_str}</td>
            </tr>
            <tr>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;">Affected Agents</td>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;color:#111827;">{agents_str}</td>
            </tr>
            <tr style="background:#f9fafb;">
              <td style="padding:9px 14px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;">Event Count</td>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;color:#111827;">{det.event_count}</td>
            </tr>
            <tr>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;font-weight:700;color:#6b7280;">Detected At</td>
              <td style="padding:9px 14px;border:1px solid #e5e7eb;color:#111827;">{det.detected_at.strftime('%Y-%m-%d %H:%M UTC') if det.detected_at else 'N/A'}</td>
            </tr>
          </table>
          <div style="margin-top:20px;padding:14px 16px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;">
            <div style="font-weight:700;color:#991b1b;margin-bottom:6px;">&#9888; Recommended Actions</div>
            <ul style="margin:0;padding-left:18px;color:#7f1d1d;font-size:13px;">
              {''.join(f'<li>{a}</li>' for a in det.get_details().get('descriptions', ['Review detection details immediately'])[:3])}
            </ul>
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:16px 30px;background:#f9fafb;text-align:center;color:#9ca3af;font-size:11px;">
          ByteIT SentinelX &bull; Automated ITDR/XDR Response &bull; Beta-v19
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body>
</html>"""

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'[ITDR ALERT] {sev_badge}: {det.rule_name}'
    msg['From']    = f'ByteIT SentinelX <{Config.SMTP_USERNAME}>'
    msg['To']      = recipient
    msg.attach(MIMEText(html, 'html'))

    with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as srv:
        if Config.SMTP_USE_TLS:
            srv.starttls()
        srv.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
        srv.sendmail(Config.SMTP_USERNAME, [recipient], msg.as_string())

    logger.info(f'ITDR alert email sent to {recipient} for detection {det.rule_id}')


def _post_webhook(policy, det) -> str:
    """POST detection data to the configured webhook URL."""
    url = policy.action_webhook_url
    if not url:
        raise ValueError('No webhook URL configured in policy')

    payload = {
        'event':        'itdr_detection',
        'detection_id': det.detection_id,
        'rule_id':      det.rule_id,
        'rule_name':    det.rule_name,
        'category':     det.category,
        'severity':     det.severity,
        'source_ip':    det.source_ip or '',
        'target_agents':det.get_target_agents(),
        'event_count':  det.event_count,
        'detected_at':  det.detected_at.isoformat() if det.detected_at else '',
    }

    headers = {'Content-Type': 'application/json'}
    if policy.action_webhook_secret:
        headers['X-SentinelX-Token'] = policy.action_webhook_secret

    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.text


def _escalate_incident(app, det):
    """Escalate the detection's parent incident severity to critical."""
    from models import db, XDRIncident
    if not det.incident_id:
        return
    inc = XDRIncident.query.get(det.incident_id)
    if inc:
        inc.severity   = 'critical'
        inc.status     = 'investigating'
        inc.updated_at = datetime.utcnow()
        db.session.commit()
