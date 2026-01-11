import logging
import json
from datetime import datetime
from flask import Blueprint, jsonify, redirect, url_for, flash, render_template, request
from flask_login import login_required, current_user
from models import AlertConfig, ReportConfig, SystemConfig, db
from email_alerts import EmailAlerts
from report_generator import ReportGenerator
import scheduler

# Create a blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)

@admin_bp.before_request
def check_admin():
    """Ensure only admin users can access admin routes"""
    if not current_user.is_authenticated or not current_user.is_admin():
        flash('Access denied: Admin privileges required', 'danger')
        return redirect(url_for('auth.login'))


@admin_bp.route('/run-scheduler-jobs')
@login_required
def run_scheduler_jobs():
    """
    Manually trigger scheduler to update its jobs with latest configuration
    Admin only route for maintenance purposes
    """
    try:
        scheduler.update_scheduler_jobs()
        flash('Scheduler jobs updated successfully', 'success')
    except Exception as e:
        logger.error(f"Error updating scheduler jobs: {str(e)}")
        flash(f'Error updating scheduler jobs: {str(e)}', 'danger')

    return redirect(url_for('dashboard.index'))


@admin_bp.route('/test-alerts')
@login_required
def test_alerts():
    """
    Manually trigger alert checks for all enabled alert configurations
    Admin only route for testing purposes
    This will always send a test email even if no alerts are found
    """
    try:
        # Check if there are any enabled alert configurations
        alert_configs = AlertConfig.query.filter_by(enabled=True).all()

        if not alert_configs:
            flash('No enabled alert configurations found. Please create and enable an alert configuration first.', 'warning')
            return redirect(url_for('alerts.index'))

        # Log the enabled alert configurations
        logger.info(f"Found {len(alert_configs)} enabled alert configurations for manual trigger")
        for alert in alert_configs:
            logger.info(f"Alert ID {alert.id}, Name: {alert.name}, Recipient: {alert.email_recipient}")

        # Force run the alerts regardless of notify_time
        email_alerts = EmailAlerts()
        opensearch_api = email_alerts.opensearch

        # Set time range for fetching alerts (default to last hour for manual trigger)
        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - scheduler.timedelta(hours=1)).isoformat()

        success_count = 0
        error_count = 0

        # Process each alert configuration
        for alert_config in alert_configs:
            try:
                # Get severity levels from config
                severity_levels = alert_config.get_alert_levels()
                recipient = alert_config.email_recipient

                logger.info(f"Manually checking alerts for config ID {alert_config.id}, levels: {severity_levels}")

                # Fetch alerts based on configuration
                alerts_data = None
                try:
                    alerts_data = opensearch_api.search_alerts(
                        severity_levels=severity_levels,
                        start_time=start_time,
                        end_time=end_time,
                        limit=50
                    )
                except Exception as e:
                    logger.error(f"Error fetching alerts from OpenSearch: {str(e)}")
                    # Continue with a test alert even if OpenSearch is unavailable
                    alerts_data = {
                        'results': [],
                        'total': 0,
                        'manual_test': True,
                        'connection_error': True,
                        'error_message': str(e)
                    }

                if alerts_data and 'error' in alerts_data:
                    logger.error(f"Error in OpenSearch response: {alerts_data['error']}")
                    # Continue with a test alert
                    alerts_data = {
                        'results': [],
                        'total': 0,
                        'manual_test': True,
                        'connection_error': True,
                        'error_message': alerts_data['error']
                    }

                # For manual testing, always send an email even if no alerts are found
                if not alerts_data or not alerts_data.get('results', []):
                    logger.info(f"No alerts found for levels: {', '.join(severity_levels)} - sending test email anyway")
                    # Create a test alert for manual testing
                    alerts_data = {
                        'results': [],
                        'total': 0,
                        'manual_test': True
                    }

                # Send the alert
                logger.info(f"Manually sending alert for config ID {alert_config.id} to {recipient}")
                result = email_alerts.send_severity_alert(alert_config, alerts_data)

                if result:
                    logger.info(f"Successfully sent test alert for config ID {alert_config.id}")
                    success_count += 1
                else:
                    logger.error(f"Failed to send test alert for config ID {alert_config.id}")
                    error_count += 1

            except Exception as e:
                logger.error(f"Error processing alert config {alert_config.id} for manual email: {str(e)}")
                error_count += 1

        if success_count > 0 and error_count == 0:
            flash(f'Successfully sent {success_count} test alerts.', 'success')
        elif success_count > 0 and error_count > 0:
            flash(f'Sent {success_count} test alerts, but {error_count} failed. Check logs for details.', 'warning')
        else:
            flash('Failed to send any test alerts. Check logs for details.', 'danger')

    except Exception as e:
        logger.error(f"Error in manual test_alerts: {str(e)}")
        flash(f'Error testing alerts: {str(e)}', 'danger')

    return redirect(url_for('alerts.index'))


@admin_bp.route('/test-scheduled-reports', methods=['POST'])
@login_required
def test_scheduled_reports():
    """
    Manually trigger the scheduled report check (same as what runs every minute)
    """
    try:
        logger.info("Manual trigger of scheduled report check initiated")

        # Import here to avoid circular imports
        from scheduler import generate_and_send_reports

        # Run the same function that the scheduler runs
        generate_and_send_reports()

        flash('Scheduled report check completed. Check logs for details.', 'info')
        return redirect(url_for('admin.scheduler'))

    except Exception as e:
        logger.error(f"Error in manual scheduled report check: {str(e)}")
        flash(f'Error testing scheduled reports: {str(e)}', 'danger')
        return redirect(url_for('admin.scheduler'))

@admin_bp.route('/test-reports', methods=['POST'])
@login_required
def test_reports():
    """
    Manually trigger report generation for all enabled report configurations
    Admin only route for testing purposes
    """
    try:
        # Check if there are any enabled report configurations
        report_configs = ReportConfig.query.filter_by(enabled=True).all()

        if not report_configs:
            flash('No enabled report configurations found', 'warning')
            return redirect(url_for('reports.index'))

        # Log the enabled report configurations
        logger.info(f"Found {len(report_configs)} enabled report configurations for manual trigger")
        for report in report_configs:
            recipients = report.get_recipients()
            logger.info(f"Report ID {report.id}, Name: {report.name}, Recipients: {recipients}")

        # Force run the reports regardless of schedule
        report_generator = ReportGenerator()
        email_alerts = EmailAlerts()
        now = datetime.utcnow()

        # Generate a report for each configuration and send it
        for report_config in report_configs:
            try:
                # Set time range for the report (last 24 hours by default)
                start_time = (now - scheduler.timedelta(days=1)).isoformat()
                end_time = now.isoformat()

                # Generate report
                logger.info(f"Manually generating report for config ID {report_config.id}")
                report = report_generator.generate_report(
                    report_config=report_config,
                    start_time=start_time,
                    end_time=end_time,
                    format=report_config.format
                )

                # If report generation was successful, send it via email
                if report:
                    # Get recipients
                    recipients = report_config.get_recipients()
                    if not recipients:
                        logger.error(f"No recipients specified for report config {report_config.id}")
                        continue

                    # Send to each recipient
                    for recipient in recipients:
                        subject = f"Security Report: {report_config.name} - {now.strftime('%Y-%m-%d')} (Manual)"
                        message = f"Attached is your manually triggered security report: {report_config.name}"

                        # Prepare attachment
                        filename = f"security_report_{report_config.name.replace(' ', '_')}_{now.strftime('%Y%m%d')}"
                        if report_config.format == 'pdf':
                            mime_type = 'application/pdf'
                            filename += '.pdf'
                        else:
                            mime_type = 'text/html'
                            filename += '.html'

                        attachments = [{
                            'content': report,
                            'filename': filename,
                            'mime_type': mime_type
                        }]

                        # Send email with attachment
                        logger.info(f"Manually sending report to {recipient}")
                        result = email_alerts.send_alert_email(
                            recipient=recipient,
                            subject=subject,
                            message=message,
                            attachments=attachments
                        )

                        if result:
                            logger.info(f"Successfully sent manual report to {recipient}")
                        else:
                            logger.error(f"Failed to send manual report to {recipient}")
                else:
                    logger.error(f"Failed to generate report for config {report_config.id}")
            except Exception as e:
                logger.error(f"Error processing report config {report_config.id}: {str(e)}")

        flash('Report generation triggered manually', 'success')
    except Exception as e:
        logger.error(f"Error running manual report generation: {str(e)}")
        flash(f'Error generating reports: {str(e)}', 'danger')

    return redirect(url_for('reports.index'))


@admin_bp.route('/scheduler')
@login_required
def scheduler_management():
    """
    Display scheduler management page with job status and configuration
    """
    try:
        # Get scheduler jobs
        jobs = []
        for job in scheduler.scheduler.get_jobs():
            job_info = {
                'id': job.id,
                'func_name': job.func.__name__,
                'interval': f"Every {job.trigger.interval.seconds // 60} minutes",
                'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'Not scheduled'
            }
            jobs.append(job_info)

        # Get system configuration
        system_configs = SystemConfig.query.all()

        # Get alert and report counts
        alert_count = AlertConfig.query.filter_by(enabled=True).count()
        report_count = ReportConfig.query.filter_by(enabled=True).count()

        # Get alert check interval
        alert_interval = SystemConfig.get_value('alert_check_interval', '15')

        # For now, set last run to None (we could track this in the database in the future)
        alert_last_run = None
        report_last_run = None

        return render_template(
            'scheduler.html',
            jobs=jobs,
            system_configs=system_configs,
            alert_count=alert_count,
            report_count=report_count,
            alert_interval=alert_interval,
            alert_last_run=alert_last_run,
            report_last_run=report_last_run
        )
    except Exception as e:
        logger.error(f"Error in scheduler management page: {str(e)}")
        flash(f'Error loading scheduler management: {str(e)}', 'danger')
        return redirect(url_for('dashboard.index'))


@admin_bp.route('/ai-config', methods=['GET', 'POST'])
@login_required
def ai_config():
    """
    Configure AI platform settings - admin only
    Allows setting the default AI provider and viewing available options
    """
    from config import Config
    
    try:
        current_default = SystemConfig.get_value('default_ai_provider', 'openai')
        
        if request.method == 'POST':
            new_provider = request.form.get('default_ai_provider', 'openai')
            
            # Validate provider
            available_providers = []
            if Config.OPENAI_API_KEY:
                available_providers.append('openai')
            if Config.GEMINI_API_KEY and Config.GEMINI_BASE_URL:
                available_providers.append('gemini')
            if Config.DEEPSEEK_API_KEY:
                available_providers.append('deepseek')
            if Config.OLLAMA_API_URL:
                available_providers.append('ollama')
            
            if new_provider not in available_providers:
                flash(f'Selected provider "{new_provider}" is not available or not configured', 'danger')
            else:
                SystemConfig.set_value('default_ai_provider', new_provider, 
                                      f'Default AI platform for AI insights and analysis')
                flash(f'Default AI provider set to {new_provider}', 'success')
                current_default = new_provider
        
        # Check which providers are available
        providers_status = {
            'openai': {
                'available': bool(Config.OPENAI_API_KEY),
                'name': 'OpenAI (GPT-4o)',
                'description': 'Advanced reasoning with OpenAI API key'
            },
            'gemini': {
                'available': bool(Config.GEMINI_API_KEY and Config.GEMINI_BASE_URL),
                'name': 'Gemini (2.5-flash)',
                'description': 'Fast reasoning via Replit AI Integrations (no API key needed)'
            },
            'deepseek': {
                'available': bool(Config.DEEPSEEK_API_KEY),
                'name': 'DeepSeek',
                'description': 'Advanced reasoning with DeepSeek API key'
            },
            'ollama': {
                'available': bool(Config.OLLAMA_API_URL),
                'name': 'Ollama (Local LLM)',
                'description': 'Local LLM deployment at ' + Config.OLLAMA_API_URL
            }
        }
        
        available_providers = [p for p, info in providers_status.items() if info['available']]
        
        return render_template(
            'ai_config.html',
            current_default=current_default,
            providers_status=providers_status,
            available_providers=available_providers
        )
    except Exception as e:
        logger.error(f"Error in AI configuration: {str(e)}")
        flash(f'Error loading AI configuration: {str(e)}', 'danger')
        return redirect(url_for('dashboard.index'))