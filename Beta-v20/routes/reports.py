from flask import Blueprint, render_template, request, jsonify, make_response, flash, redirect, url_for, send_file
from flask_login import login_required, current_user
import logging
from datetime import datetime, timedelta
import json
from app import db
from models import ReportConfig
from report_generator import ReportGenerator
from email_alerts import EmailAlerts

logger = logging.getLogger(__name__)

reports_bp = Blueprint('reports', __name__)


def _downloaded_at_pkt():
    """Return current time as PKT (UTC+5) formatted string."""
    return (datetime.utcnow() + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S PKT')


def _user_label():
    """Return a readable label for the currently-logged-in user."""
    try:
        name_parts = []
        if hasattr(current_user, 'username') and current_user.username:
            name_parts.append(current_user.username)
        if hasattr(current_user, 'email') and current_user.email:
            name_parts.append(f"<{current_user.email}>")
        return ' '.join(name_parts) if name_parts else 'Unknown User'
    except Exception:
        return 'Unknown User'


def _make_email_body(report_config, generated_at, downloaded_by, period_start, period_end,
                     severity_levels, total_alerts, alert_counts, logo_data_uri=''):
    """Build a professional HTML email body."""
    sev_rows = ''
    colors = {'critical': '#c0392b', 'high': '#e67e22', 'medium': '#c8980a', 'low': '#27ae60'}
    for sev in ['critical', 'high', 'medium', 'low']:
        count = alert_counts.get(sev, 0) or 0
        if count:
            color = colors.get(sev, '#6b7280')
            sev_rows += f'''
            <tr>
              <td style="padding:7px 14px;border-bottom:1px solid #e5e7eb;font-size:13px;text-transform:capitalize;">{sev.capitalize()}</td>
              <td style="padding:7px 14px;border-bottom:1px solid #e5e7eb;text-align:center;">
                <span style="background:{color}22;color:{color};font-weight:700;padding:2px 10px;border-radius:12px;font-size:12px;">{count}</span>
              </td>
            </tr>'''

    logo_html = ''
    if logo_data_uri:
        logo_html = f'<img src="{logo_data_uri}" width="56" height="56" style="object-fit:contain;background:#fff;border-radius:8px;padding:4px;" alt="ByteIT Logo">'
    else:
        logo_html = '<div style="width:56px;height:56px;background:rgba(255,255,255,0.2);border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:16px;color:#fff;">BI</div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Segoe UI,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 0;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

  <!-- HEADER -->
  <tr>
    <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 60%,#0057b8 100%);padding:28px 32px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="70" style="vertical-align:middle;">{logo_html}</td>
          <td style="padding-left:16px;vertical-align:middle;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:rgba(255,255,255,0.65);margin-bottom:4px;">ByteIT SentinalX · Beta-v19</div>
            <div style="font-size:22px;font-weight:800;color:#fff;letter-spacing:0.5px;">Security Alert Report</div>
            <div style="font-size:12px;color:rgba(255,255,255,0.75);margin-top:4px;">Report: <strong style="color:#fff;">{report_config.name}</strong></div>
          </td>
          <td style="text-align:right;vertical-align:middle;">
            <div style="font-size:11px;color:rgba(255,255,255,0.8);line-height:1.9;">
              <strong style="color:#fff;">Generated:</strong> {generated_at}<br>
              <strong style="color:#fff;">Downloaded By:</strong> {downloaded_by}<br>
              <strong style="color:#fff;">Total Alerts:</strong> {total_alerts}
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- ACCENT BAR -->
  <tr><td style="height:5px;background:linear-gradient(90deg,#00c9ff,#0057b8,#c0392b);"></td></tr>

  <!-- METADATA -->
  <tr>
    <td style="padding:20px 32px 0;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8faff;border:1px solid #dbeafe;border-radius:8px;padding:14px 18px;">
        <tr>
          <td style="font-size:11px;color:#6b7280;padding:4px 16px 4px 0;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;color:#9ca3af;">Reporting Period</div>
            <div style="font-weight:700;color:#0d1b4b;font-size:13px;">{period_start} → {period_end}</div>
          </td>
          <td style="font-size:11px;color:#6b7280;padding:4px 16px;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;color:#9ca3af;">Severity Scope</div>
            <div style="font-weight:700;color:#0d1b4b;font-size:13px;">{", ".join(s.capitalize() for s in severity_levels)}</div>
          </td>
          <td style="font-size:11px;color:#6b7280;padding:4px 0 4px 16px;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;color:#9ca3af;">Timezone</div>
            <div style="font-weight:700;color:#0d1b4b;font-size:13px;">PKT (UTC+5)</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- SUMMARY STATS -->
  <tr>
    <td style="padding:20px 32px 0;">
      <div style="font-size:14px;font-weight:700;color:#0d1b4b;border-left:4px solid #0057b8;padding-left:10px;background:#f0f4ff;border-radius:0 4px 4px 0;margin-bottom:14px;line-height:2;">Executive Summary</div>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="padding:0 6px;">
            <div style="background:#fff;border:1px solid #e0e7ff;border-top:4px solid #0057b8;border-radius:8px;padding:14px 10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
              <div style="font-size:26px;font-weight:800;color:#0057b8;">{total_alerts}</div>
              <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;">Total</div>
            </div>
          </td>
          <td align="center" style="padding:0 6px;">
            <div style="background:#fff;border:1px solid #e0e7ff;border-top:4px solid #c0392b;border-radius:8px;padding:14px 10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
              <div style="font-size:26px;font-weight:800;color:#c0392b;">{alert_counts.get("critical", 0) or 0}</div>
              <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;">Critical</div>
            </div>
          </td>
          <td align="center" style="padding:0 6px;">
            <div style="background:#fff;border:1px solid #e0e7ff;border-top:4px solid #e67e22;border-radius:8px;padding:14px 10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
              <div style="font-size:26px;font-weight:800;color:#e67e22;">{alert_counts.get("high", 0) or 0}</div>
              <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;">High</div>
            </div>
          </td>
          <td align="center" style="padding:0 6px;">
            <div style="background:#fff;border:1px solid #e0e7ff;border-top:4px solid #f1c40f;border-radius:8px;padding:14px 10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
              <div style="font-size:26px;font-weight:800;color:#c8980a;">{alert_counts.get("medium", 0) or 0}</div>
              <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;">Medium</div>
            </div>
          </td>
          <td align="center" style="padding:0 6px;">
            <div style="background:#fff;border:1px solid #e0e7ff;border-top:4px solid #27ae60;border-radius:8px;padding:14px 10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
              <div style="font-size:26px;font-weight:800;color:#27ae60;">{alert_counts.get("low", 0) or 0}</div>
              <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;">Low</div>
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- BREAKDOWN TABLE -->
  <tr>
    <td style="padding:20px 32px 0;">
      <div style="font-size:14px;font-weight:700;color:#0d1b4b;border-left:4px solid #0057b8;padding-left:10px;background:#f0f4ff;border-radius:0 4px 4px 0;margin-bottom:14px;line-height:2;">Severity Breakdown</div>
      <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
        <tr style="background:#0d1b4b;">
          <th style="padding:9px 14px;text-align:left;color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Severity</th>
          <th style="padding:9px 14px;text-align:center;color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Alert Count</th>
        </tr>
        {sev_rows if sev_rows else '<tr><td colspan="2" style="padding:12px 14px;text-align:center;color:#6b7280;font-size:12px;">No alerts in this period.</td></tr>'}
      </table>
    </td>
  </tr>

  <!-- ATTACHMENT NOTE -->
  <tr>
    <td style="padding:20px 32px 0;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:14px 18px;">
        <tr>
          <td style="vertical-align:middle;width:24px;font-size:18px;">📎</td>
          <td style="padding-left:12px;font-size:12px;color:#92400e;">
            {'The full report is attached as a PDF to this email. Open the attachment for complete alert details and full logs.' if report_config.format == 'pdf' else 'The full HTML report with complete alert details and logs is included below.'}
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- FOOTER -->
  <tr>
    <td style="padding:24px 32px 0;">
      <div style="height:3px;background:linear-gradient(90deg,#00c9ff,#0057b8,#c0392b);border-radius:2px;"></div>
    </td>
  </tr>
  <tr>
    <td style="background:linear-gradient(135deg,#0d1b4b 0%,#1a3a8f 100%);padding:18px 32px;border-radius:0 0 12px 12px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="color:rgba(255,255,255,0.7);font-size:11px;line-height:1.8;">
            <strong style="color:#fff;">ByteIT SentinalX</strong> · Beta-v19<br>
            Created by Ali Zaib · IT Department<br>
            <a href="mailto:itsupport@rebiz.com" style="color:#93c5fd;">itsupport@rebiz.com</a>
          </td>
          <td style="text-align:right;vertical-align:middle;">
            <span style="background:rgba(255,255,255,0.12);color:#fff;border-radius:10px;padding:3px 12px;font-size:10px;font-weight:600;letter-spacing:0.5px;">CONFIDENTIAL</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>'''


@reports_bp.route('/reports')
@login_required
def index():
    reports = ReportConfig.query.filter_by(user_id=current_user.id).all()
    return render_template('reports.html', reports=reports)


@reports_bp.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    try:
        reports = ReportConfig.query.filter_by(user_id=current_user.id).all()
        reports_list = []
        for report in reports:
            reports_list.append({
                'id': report.id,
                'name': report.name,
                'severity_levels': report.get_severity_levels(),
                'format': report.format,
                'schedule': report.schedule,
                'schedule_time': report.schedule_time,
                'recipients': report.get_recipients(),
                'enabled': report.enabled,
                'created_at': report.created_at.isoformat()
            })
        return jsonify(reports_list)
    except Exception as e:
        logger.error(f"Error getting reports: {str(e)}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/reports', methods=['POST'])
@login_required
def create_report():
    try:
        data = request.json
        if not data.get('name'):
            return jsonify({'error': 'Report name is required'}), 400
        if not data.get('severity_levels'):
            return jsonify({'error': 'At least one severity level must be selected'}), 400
        if not data.get('recipients'):
            return jsonify({'error': 'At least one recipient email is required'}), 400

        schedule_time = data.get('schedule_time')
        if schedule_time:
            import re
            if not re.match(r'^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$', schedule_time):
                return jsonify({'error': 'Schedule time must be in 24-hour format (HH:MM)'}), 400

        new_report = ReportConfig(
            user_id=current_user.id,
            name=data.get('name'),
            format=data.get('format', 'pdf'),
            schedule=data.get('schedule'),
            schedule_time=data.get('schedule_time'),
            enabled=data.get('enabled', True)
        )
        new_report.set_severity_levels(data.get('severity_levels'))
        new_report.set_recipients(data.get('recipients'))
        db.session.add(new_report)
        db.session.commit()
        return jsonify({'id': new_report.id, 'name': new_report.name,
                        'message': 'Report configuration created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/reports/<int:report_id>', methods=['PUT'])
@login_required
def update_report(report_id):
    try:
        report = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()
        if not report:
            return jsonify({'error': 'Report not found'}), 404

        data = request.json
        if 'name' in data:
            report.name = data['name']
        if 'severity_levels' in data:
            report.set_severity_levels(data['severity_levels'])
        if 'format' in data:
            report.format = data['format']
        if 'schedule' in data:
            report.schedule = data['schedule']
        if 'schedule_time' in data:
            schedule_time = data['schedule_time']
            if schedule_time:
                import re
                if not re.match(r'^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$', schedule_time):
                    return jsonify({'error': 'Schedule time must be in 24-hour format (HH:MM)'}), 400
            report.schedule_time = schedule_time
        if 'recipients' in data:
            report.set_recipients(data['recipients'])
        if 'enabled' in data:
            report.enabled = data['enabled']

        db.session.commit()
        return jsonify({'id': report.id, 'message': 'Report configuration updated successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/reports/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    try:
        report = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        db.session.delete(report)
        db.session.commit()
        return jsonify({'message': 'Report configuration deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/reports/generate', methods=['POST'])
@login_required
def generate_report_api():
    """Generate a report on demand (download)."""
    try:
        data = request.json
        report_generator = ReportGenerator()

        end_time = datetime.utcnow().isoformat()
        time_range = data.get('time_range', '24h')
        if time_range == '24h':
            start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()
        elif time_range == '7d':
            start_time = (datetime.utcnow() - timedelta(days=7)).isoformat()
        elif time_range == '30d':
            start_time = (datetime.utcnow() - timedelta(days=30)).isoformat()
        elif time_range == '60d':
            start_time = (datetime.utcnow() - timedelta(days=60)).isoformat()
        elif time_range == '90d':
            start_time = (datetime.utcnow() - timedelta(days=90)).isoformat()
        else:
            start_time = data.get('start_time')
            end_time = data.get('end_time', end_time)

        report_config = {
            'severity_levels': data.get('severity_levels', ['critical', 'high', 'medium', 'low']),
            'format': data.get('format', 'pdf')
        }

        if report_config['format'] == 'pdf' and not report_generator.is_pdf_available():
            return jsonify({'error': 'PDF generation is not available. System dependencies are missing. Please use HTML format instead.'}), 400

        downloaded_by = _user_label()
        downloaded_at = _downloaded_at_pkt()

        report = report_generator.generate_report(
            report_config=report_config,
            start_time=start_time,
            end_time=end_time,
            format=report_config['format'],
            downloaded_by=downloaded_by,
            downloaded_at=downloaded_at,
        )

        if not report:
            return jsonify({'error': 'Failed to generate report'}), 500

        if report_config['format'].lower() == 'html':
            return jsonify({'html': report})
        else:
            response = make_response(report.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=sentinalx_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            return response
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/reports/<int:report_id>/generate', methods=['GET'])
@login_required
def generate_specific_report(report_id):
    """Generate a specific saved report configuration (download)."""
    try:
        report_config = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()
        if not report_config:
            return jsonify({'error': 'Report not found'}), 404

        report_generator = ReportGenerator()
        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()

        if report_config.format == 'pdf' and not report_generator.is_pdf_available():
            return jsonify({'error': 'PDF generation is not available. System dependencies are missing. Please use HTML format instead.'}), 400

        downloaded_by = _user_label()
        downloaded_at = _downloaded_at_pkt()

        report = report_generator.generate_report(
            report_config=report_config,
            start_time=start_time,
            end_time=end_time,
            format=report_config.format,
            downloaded_by=downloaded_by,
            downloaded_at=downloaded_at,
        )

        if not report:
            return jsonify({'error': 'Failed to generate report'}), 500

        if report_config.format.lower() == 'html':
            return jsonify({'html': report})
        else:
            response = make_response(report.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=sentinalx_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            return response
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/reports/<int:report_id>/send', methods=['POST'])
@login_required
def send_report_email(report_id):
    """Send a report by email with a professional HTML body."""
    try:
        report_config = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()
        if not report_config:
            return jsonify({'error': 'Report not found'}), 404

        report_generator = ReportGenerator()
        email_alerts = EmailAlerts()

        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()

        if report_config.format == 'pdf' and not report_generator.is_pdf_available():
            return jsonify({'error': 'PDF generation is not available. System dependencies are missing. Please use HTML format instead.'}), 400

        downloaded_by = _user_label()
        downloaded_at = _downloaded_at_pkt()

        # Generate the actual report document
        report = report_generator.generate_report(
            report_config=report_config,
            start_time=start_time,
            end_time=end_time,
            format=report_config.format,
            downloaded_by=downloaded_by,
            downloaded_at=downloaded_at,
        )

        if not report:
            return jsonify({'error': 'Failed to generate report'}), 500

        # Build the professional email body
        now_pkt = (datetime.utcnow() + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S PKT')
        try:
            start_pkt = (datetime.fromisoformat(start_time) + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S PKT')
            end_pkt = (datetime.fromisoformat(end_time) + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S PKT')
        except Exception:
            start_pkt, end_pkt = start_time, end_time

        # Fetch alert counts for the email summary
        try:
            from report_generator import ReportGenerator as RG
            rg = RG()
            alert_counts = rg.opensearch.get_alert_count_by_severity(
                start_time=start_time, end_time=end_time
            )
            total_alerts = sum(alert_counts.get(s, 0) or 0 for s in ['critical', 'high', 'medium', 'low'])
        except Exception:
            alert_counts = {}
            total_alerts = 0

        from report_generator import _get_logo_base64
        logo_data_uri = _get_logo_base64()

        email_body = _make_email_body(
            report_config=report_config,
            generated_at=now_pkt,
            downloaded_by=downloaded_by,
            period_start=start_pkt,
            period_end=end_pkt,
            severity_levels=report_config.get_severity_levels(),
            total_alerts=total_alerts,
            alert_counts=alert_counts,
            logo_data_uri=logo_data_uri,
        )

        subject = f"ByteIT SentinalX — Security Report: {report_config.name} [{now_pkt}]"

        # Prepare attachment for PDF format
        attachments = None
        if report_config.format.lower() == 'pdf':
            attachments = [{
                'content': report,
                'filename': f"sentinalx_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                'mime_type': 'application/pdf'
            }]
        else:
            # For HTML format, the report IS the email body
            email_body = report

        recipients = report_config.get_recipients()
        success = True
        for recipient in recipients:
            if not email_alerts.send_alert_email(recipient, subject, email_body, attachments):
                success = False

        if success:
            return jsonify({'message': f'Report sent successfully to {len(recipients)} recipients'})
        else:
            return jsonify({'error': 'Failed to send report to some or all recipients'}), 500
    except Exception as e:
        logger.error(f"Error sending report email: {str(e)}")
        return jsonify({'error': str(e)}), 500
