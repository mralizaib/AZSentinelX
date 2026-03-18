# Adding WeasyPrint availability check for PDF generation

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

@reports_bp.route('/reports')
@login_required
def index():
    # Get user's report configurations
    reports = ReportConfig.query.filter_by(user_id=current_user.id).all()
    return render_template('reports.html', reports=reports)

@reports_bp.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    """Get all report configurations for the current user"""
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
    """Create a new report configuration"""
    try:
        data = request.json

        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Report name is required'}), 400

        if not data.get('severity_levels'):
            return jsonify({'error': 'At least one severity level must be selected'}), 400

        if not data.get('recipients'):
            return jsonify({'error': 'At least one recipient email is required'}), 400

        # Validate time format if provided
        schedule_time = data.get('schedule_time')
        if schedule_time:
            import re
            time_pattern = r'^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$'
            if not re.match(time_pattern, schedule_time):
                return jsonify({'error': 'Schedule time must be in 24-hour format (HH:MM)'}), 400

        # Create new report configuration
        new_report = ReportConfig(
            user_id=current_user.id,
            name=data.get('name'),
            format=data.get('format', 'pdf'),
            schedule=data.get('schedule'),
            schedule_time=data.get('schedule_time'),
            enabled=data.get('enabled', True)
        )

        # Set JSON fields
        new_report.set_severity_levels(data.get('severity_levels'))
        new_report.set_recipients(data.get('recipients'))

        # Save to database
        db.session.add(new_report)
        db.session.commit()

        return jsonify({
            'id': new_report.id,
            'name': new_report.name,
            'message': 'Report configuration created successfully'
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@reports_bp.route('/api/reports/<int:report_id>', methods=['PUT'])
@login_required
def update_report(report_id):
    """Update an existing report configuration"""
    try:
        report = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()

        if not report:
            return jsonify({'error': 'Report not found'}), 404

        data = request.json

        # Update fields if provided
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
                time_pattern = r'^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$'
                if not re.match(time_pattern, schedule_time):
                    return jsonify({'error': 'Schedule time must be in 24-hour format (HH:MM)'}), 400
            report.schedule_time = schedule_time

        if 'recipients' in data:
            report.set_recipients(data['recipients'])

        if 'enabled' in data:
            report.enabled = data['enabled']

        # Save changes
        db.session.commit()

        return jsonify({
            'id': report.id,
            'message': 'Report configuration updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@reports_bp.route('/api/reports/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    """Delete a report configuration"""
    try:
        report = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()

        if not report:
            return jsonify({'error': 'Report not found'}), 404

        db.session.delete(report)
        db.session.commit()

        return jsonify({
            'message': 'Report configuration deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@reports_bp.route('/api/reports/generate', methods=['POST'])
@login_required
def generate_report_api():
    """Generate a report on demand"""
    try:
        data = request.json
        report_generator = ReportGenerator()

        # Get time range
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
            # Custom time range
            start_time = data.get('start_time')
            end_time = data.get('end_time', end_time)

        # Get report configuration
        report_config = {
            'severity_levels': data.get('severity_levels', ['critical', 'high', 'medium', 'low']),
            'format': data.get('format', 'pdf')
        }

        # Generate report
        report_generator = ReportGenerator()

        # Check if PDF is requested but WeasyPrint is not available
        if report_config['format'] == 'pdf' and not report_generator.is_pdf_available():
            return jsonify({'error': 'PDF generation is not available. System dependencies are missing. Please use HTML format instead.'}), 400

        report = report_generator.generate_report(
            report_config=report_config,
            start_time=start_time,
            end_time=end_time,
            format=report_config['format']
        )

        if not report:
            return jsonify({'error': 'Failed to generate report'}), 500

        # Return HTML directly or PDF as attachment
        if report_config['format'].lower() == 'html':
            return jsonify({'html': report})
        else:
            response = make_response(report.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            return response
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@reports_bp.route('/api/reports/<int:report_id>/generate', methods=['GET'])
@login_required
def generate_specific_report(report_id):
    """Generate a specific report configuration"""
    try:
        report_config = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()

        if not report_config:
            return jsonify({'error': 'Report not found'}), 404

        report_generator = ReportGenerator()

        # Default to last 24 hours
        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()

        # Check if PDF is requested but WeasyPrint is not available
        if report_config.format == 'pdf' and not report_generator.is_pdf_available():
            return jsonify({'error': 'PDF generation is not available. System dependencies are missing. Please use HTML format instead.'}), 400

        # Generate report
        report = report_generator.generate_report(
            report_config=report_config,
            start_time=start_time,
            end_time=end_time,
            format=report_config.format
        )

        if not report:
            return jsonify({'error': 'Failed to generate report'}), 500

        # Return HTML directly or PDF as attachment
        if report_config.format.lower() == 'html':
            return jsonify({'html': report})
        else:
            response = make_response(report.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            return response
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@reports_bp.route('/api/reports/<int:report_id>/send', methods=['POST'])
@login_required
def send_report_email(report_id):
    """Send a report by email"""
    try:
        report_config = ReportConfig.query.filter_by(id=report_id, user_id=current_user.id).first()

        if not report_config:
            return jsonify({'error': 'Report not found'}), 404

        report_generator = ReportGenerator()
        email_alerts = EmailAlerts()

        # Default to last 24 hours
        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()

        # Check if PDF is requested but WeasyPrint is not available
        if report_config.format == 'pdf' and not report_generator.is_pdf_available():
            return jsonify({'error': 'PDF generation is not available. System dependencies are missing. Please use HTML format instead.'}), 400

        # Generate report
        report = report_generator.generate_report(
            report_config=report_config,
            start_time=start_time,
            end_time=end_time,
            format=report_config.format
        )

        if not report:
            return jsonify({'error': 'Failed to generate report'}), 500

        # Prepare email
        subject = f"Security Report: {report_config.name} - {datetime.now().strftime('%Y-%m-%d')}"

        # Simple email body
        message = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
            </style>
        </head>
        <body>
            <h1>Security Report</h1>
            <p>Please find attached the security report "{report_config.name}" generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.</p>
            <p>This report includes security alerts with the following severity levels: {', '.join(report_config.get_severity_levels())}.</p>
            <p>This is an automated email from AZ Sentinel X.</p>
        </body>
        </html>
        """

        # Prepare attachment if needed
        attachments = None
        if report_config.format.lower() == 'pdf':
            attachments = [{
                'content': report,
                'filename': f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                'mime_type': 'application/pdf'
            }]
        else:
            # For HTML reports, include the content in the email
            message = report

        # Send to all recipients
        recipients = report_config.get_recipients()
        success = True

        for recipient in recipients:
            if not email_alerts.send_alert_email(recipient, subject, message, attachments):
                success = False

        if success:
            return jsonify({'message': f'Report sent successfully to {len(recipients)} recipients'})
        else:
            return jsonify({'error': 'Failed to send report to some or all recipients'}), 500
    except Exception as e:
        logger.error(f"Error sending report email: {str(e)}")
        return jsonify({'error': str(e)}), 500