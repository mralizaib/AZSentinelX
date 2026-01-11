import logging
from datetime import datetime, timedelta
import json
import re
from flask_apscheduler import APScheduler
from models import AlertConfig, ReportConfig, SystemConfig, db, StoredAlert
from email_alerts import EmailAlerts
from report_generator import ReportGenerator
from opensearch_api import OpenSearchAPI


def normalize_time(time_str):
    """
    Normalize various time formats to HH:MM format

    Args:
        time_str: Time string in various formats (HH:MM, H:MM, or HH:MM:SS)

    Returns:
        Normalized time string in HH:MM format
    """
    if not time_str:
        return None

    original_time = time_str    
    try:
        # Handle string formats with colons (HH:MM, H:MM, or HH:MM:SS)
        if ':' in time_str:
            # Use regex to extract hours and minutes
            match = re.match(r'(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?', time_str.strip())
            if match:
                hour = int(match.group(1))
                minute = int(match.group(2))
                # Ensure valid hour and minute ranges
                if 0 <= hour <= 23 and 0 <= minute <= 59:
                    normalized = f"{hour:02d}:{minute:02d}"
                    logger.debug(f"Time normalization: '{original_time}' → '{normalized}' (colon format)")
                    return normalized
                else:
                    logger.warning(f"Invalid time values - hour: {hour}, minute: {minute}")
                    return None
            else:
                logger.warning(f"Time format not recognized (has colon but didn't match pattern): {time_str}")
                return None
        else:
            # Try to parse as integer (hour only)
            try:
                hour = int(time_str.strip())
                if 0 <= hour <= 23:
                    normalized = f"{hour:02d}:00"
                    logger.debug(f"Time normalization: '{original_time}' → '{normalized}' (hour only)")
                    return normalized
            except ValueError:
                pass
            logger.warning(f"Time format not recognized (no colon): {time_str}")
            return None
    except Exception as e:
        logger.error(f"Error normalizing time '{time_str}': {str(e)}")
        return None

logger = logging.getLogger(__name__)

# Initialize the scheduler
scheduler = APScheduler()

# Define the jobs to be run
def store_alerts_in_database():
    """
    Store alerts from OpenSearch in database on a date-wise basis.
    This trains the AI search engine with historical alert data.
    """
    logger.info("Running alert storage job for AI search training")
    
    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return
    
    try:
        with scheduler.app.app_context():
            opensearch = OpenSearchAPI()
            
            # Fetch recent alerts (last 3 days for frequent training)
            end_time = datetime.utcnow().isoformat()
            start_time = (datetime.utcnow() - timedelta(days=3)).isoformat()
            
            results = opensearch.search_alerts(
                start_time=start_time,
                end_time=end_time,
                limit=1000  # Increased limit to get more training data
            )
            
            if results and 'error' not in results:
                alerts = results.get('results', [])
                stored_count = 0
                skipped_count = 0
                
                for alert in alerts:
                    try:
                        # Extract key fields
                        source = alert.get('_source', {})
                        timestamp = source.get('@timestamp')
                        alert_id = alert.get('_id', '')
                        
                        if not timestamp or not alert_id:
                            continue
                        
                        # Parse timestamp
                        try:
                            alert_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        except:
                            alert_dt = datetime.utcnow()
                        
                        alert_date = alert_dt.date()
                        
                        # Check if already stored
                        existing = StoredAlert.query.filter_by(alert_id=alert_id).first()
                        if existing:
                            skipped_count += 1
                            continue
                        
                        # Extract security data - handle Windows and generic events
                        agent = source.get('agent', {})
                        rule = source.get('rule', {})
                        data_section = source.get('data', {})
                        data_win = data_section.get('win', {})
                        eventdata = data_win.get('eventdata', {})
                        
                        # Try to extract username from multiple possible locations
                        username = (
                            eventdata.get('targetUserName') or
                            eventdata.get('SubjectUserName') or
                            eventdata.get('UserName') or
                            data_section.get('user') or
                            None
                        )
                        
                        # Extract source IP
                        source_ip = (
                            data_section.get('srcip') or
                            eventdata.get('SourceAddress') or
                            None
                        )
                        
                        # Extract destination IP
                        dest_ip = (
                            data_section.get('dstip') or
                            eventdata.get('DestinationAddress') or
                            None
                        )
                        
                        # Extract login type if available
                        login_type = eventdata.get('logonType')
                        
                        # Extract file path for FIM alerts (syscheck.path)
                        file_path = source.get('syscheck', {}).get('path')
                        
                        # Extract RDP activity if available
                        rdp_activity = None
                        if data_section.get('protocol') == 'rdp' or 'RDP' in str(source.get('rule', {}).get('description', '')):
                            rdp_activity = 'RDP_SESSION'
                        
                        # Create stored alert with comprehensive data
                        stored_alert = StoredAlert(
                            alert_date=alert_date,
                            alert_timestamp=alert_dt,
                            alert_id=alert_id,
                            agent_id=agent.get('id'),
                            agent_name=agent.get('name'),
                            agent_ip=agent.get('ip'),
                            rule_id=rule.get('id'),
                            rule_description=rule.get('description'),
                            severity_level=rule.get('level'),
                            severity_numeric=rule.get('id'),
                            source_ip=source_ip,
                            destination_ip=dest_ip,
                            username=username,
                            event_type=rule.get('groups', [''])[0] if rule.get('groups') else '',
                            login_type=login_type,
                            rdp_activity=rdp_activity,
                            file_path=file_path,
                            raw_data=json.dumps(source)[:5000]
                        )
                        
                        db.session.add(stored_alert)
                        stored_count += 1
                        
                        if stored_count % 100 == 0:
                            db.session.commit()
                            logger.info(f"Stored {stored_count} alerts, skipped {skipped_count} duplicates")
                    
                    except Exception as e:
                        logger.warning(f"Error storing alert {alert.get('_id', 'unknown')}: {str(e)}")
                        continue
                
                if stored_count > 0:
                    db.session.commit()
                logger.info(f"Alert storage job completed: {stored_count} new alerts stored, {skipped_count} duplicates skipped")
            else:
                logger.warning(f"Could not fetch alerts from OpenSearch: {results}")
    
    except Exception as e:
        logger.error(f"Error in alert storage job: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())


def check_and_send_alerts():
    """
    Check for alerts that need to be sent based on alert configurations
    This job will run at the interval defined in system config
    """
    logger.info("Running scheduled alert check job")

    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return

    try:
        # Use the application context from the scheduler
        with scheduler.app.app_context():
            # Get all enabled alert configs
            alert_configs = AlertConfig.query.filter_by(enabled=True).all()
            if not alert_configs:
                logger.info("No enabled alert configurations found")
                return

            logger.info(f"Found {len(alert_configs)} enabled alert configurations")
            email_alerts = EmailAlerts()

            # Process each alert configuration
            for alert_config in alert_configs:
                try:
                    # Check if this alert should run based on notify_time
                    should_send_alert = True

                    # For HIGH and CRITICAL alerts, check if they should be sent immediately
                    alert_levels = alert_config.get_alert_levels()
                    is_high_critical = any(level.lower() in ['high', 'critical'] for level in alert_levels)
                    
                    if is_high_critical:
                        # High and Critical alerts should be sent immediately regardless of notify_time
                        logger.info(f"Alert config {alert_config.id} has HIGH/CRITICAL levels - sending immediately")
                        should_send_alert = True
                    elif alert_config.notify_time:
                        # For other alerts, check the scheduled time
                        # Get current time in Pakistan timezone (UTC+5)
                        now_utc = datetime.utcnow()
                        now_pakistan = now_utc + timedelta(hours=5)
                        current_time_pakistan = now_pakistan.strftime('%H:%M')

                        # Normalize times for comparison
                        normalized_current_time = normalize_time(current_time_pakistan)
                        normalized_scheduled_time = normalize_time(alert_config.notify_time)

                        logger.info(f"Alert config {alert_config.id} ({alert_config.name}) - Scheduled: {normalized_scheduled_time}, Current (PKT): {normalized_current_time}")

                        # Only send if times match
                        if normalized_scheduled_time and normalized_current_time:
                            should_send_alert = (normalized_current_time == normalized_scheduled_time)
                        else:
                            logger.warning(f"Could not normalize times for alert config {alert_config.id}")
                            should_send_alert = False

                        if not should_send_alert:
                            logger.debug(f"Skipping alert config {alert_config.id} - not scheduled time")
                            continue
                    else:
                        logger.info(f"Alert config {alert_config.id} has no specific notify_time - sending immediately")

                    # Send the alert
                    logger.info(f"🚨 SENDING ALERT for config ID {alert_config.id} ({alert_config.name}) to {alert_config.email_recipient}")

                    try:
                        result = email_alerts.send_severity_alert(alert_config)
                        if result:
                            logger.info(f"✅ Successfully sent alert for config ID {alert_config.id}")
                        else:
                            logger.error(f"❌ Failed to send alert for config ID {alert_config.id} - email_alerts.send_severity_alert returned False")
                    except Exception as send_error:
                        logger.error(f"❌ Exception while sending alert for config ID {alert_config.id}: {str(send_error)}")
                        result = False

                except Exception as e:
                    logger.error(f"Error processing alert config {alert_config.id}: {str(e)}")

    except Exception as e:
        logger.error(f"Error in check_and_send_alerts job: {str(e)}")


def generate_and_send_reports():
    """
    Generate and send reports based on report configurations
    This job will run every minute and check if any reports need to be sent
    """
    logger.info("Running scheduled report generation job")

    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return

    try:
        # Use the application context from the scheduler
        with scheduler.app.app_context():
            # Get all enabled report configs
            report_configs = ReportConfig.query.filter_by(enabled=True).all()
            if not report_configs:
                logger.info("No enabled report configurations found")
                return

            logger.info(f"Found {len(report_configs)} enabled report configurations")
            report_generator = ReportGenerator()
            email_alerts = EmailAlerts()

            # Get current time in both UTC and Pakistan time
            now_utc = datetime.utcnow()
            # Pakistan Standard Time is UTC+5
            now_pakistan = now_utc + timedelta(hours=5)

            current_time_utc = now_utc.strftime('%H:%M')
            current_time_pakistan = now_pakistan.strftime('%H:%M')
            current_day = now_pakistan.strftime('%A').lower()

            logger.info(f"Current UTC time: {current_time_utc}, Pakistan time: {current_time_pakistan}, Current day: {current_day}")
            logger.info(f"Pakistan time details - Hour: {now_pakistan.hour}, Minute: {now_pakistan.minute}")

            # Process each report configuration
            for report_config in report_configs:
                try:
                    should_run = False

                    # Skip if no schedule is set
                    if not report_config.schedule or not report_config.schedule_time:
                        logger.debug(f"Report {report_config.id} has no schedule set, skipping")
                        continue

                    # Log detailed schedule information
                    logger.info(f"Checking report {report_config.id} ({report_config.name}) - Schedule: {report_config.schedule}, Time: {report_config.schedule_time}")

                    # Normalize the scheduled time (assuming it's in Pakistan time)
                    normalized_scheduled_time = normalize_time(report_config.schedule_time)
                    normalized_current_time = normalize_time(current_time_pakistan)  # Use Pakistan time

                    if not normalized_scheduled_time:
                        logger.error(f"Could not normalize scheduled time for report {report_config.id}: {report_config.schedule_time}")
                        continue

                    logger.info(f"Time comparison (Pakistan timezone) - Scheduled: '{normalized_scheduled_time}', Current: '{normalized_current_time}', Raw scheduled: '{report_config.schedule_time}'")

                    # Check if it's time to run this report
                    if report_config.schedule == 'daily':
                        should_run = normalized_scheduled_time == normalized_current_time
                        logger.info(f"Daily report check - Scheduled: {normalized_scheduled_time}, Current: {normalized_current_time}, Match: {should_run}")

                    elif report_config.schedule == 'weekly':
                        # Run on Monday (or you can make this configurable)
                        should_run = (current_day == 'monday' and normalized_scheduled_time == normalized_current_time)
                        logger.info(f"Weekly report check - Day: {current_day}, Time match: {normalized_scheduled_time == normalized_current_time}, Should run: {should_run}")

                    elif report_config.schedule == 'monthly':
                        # Run on the 1st of each month
                        should_run = (now_pakistan.day == 1 and normalized_scheduled_time == normalized_current_time)
                        logger.info(f"Monthly report check - Day: {now_pakistan.day}, Time match: {normalized_scheduled_time == normalized_current_time}, Should run: {should_run}")
                    
                    # Enhanced debug logging for afternoon/evening scheduling issues
                    if not should_run:
                        scheduled_hour = int(normalized_scheduled_time.split(':')[0]) if normalized_scheduled_time else 0
                        current_hour = int(normalized_current_time.split(':')[0]) if normalized_current_time else 0
                        
                        if scheduled_hour >= 13:
                            logger.info(f"⏰ Afternoon/evening report debugging for {report_config.name}:")
                            logger.info(f"   - Raw scheduled time: '{report_config.schedule_time}'")
                            logger.info(f"   - Normalized scheduled: '{normalized_scheduled_time}'")
                            logger.info(f"   - Normalized current: '{normalized_current_time}'")
                            logger.info(f"   - Scheduled hour: {scheduled_hour}, Current hour: {current_hour}")
                            logger.info(f"   - Schedule type: {report_config.schedule}")
                            logger.info(f"   - Current day: {current_day}")
                            logger.info(f"   - Pakistan time full: {now_pakistan.strftime('%Y-%m-%d %H:%M:%S')}")
                            
                            # Additional check for exact minute matching
                            scheduled_minute = int(normalized_scheduled_time.split(':')[1]) if normalized_scheduled_time else 0
                            current_minute = int(normalized_current_time.split(':')[1]) if normalized_current_time else 0
                            logger.info(f"   - Scheduled minute: {scheduled_minute}, Current minute: {current_minute}")
                            
                            # Force run if we're within 1 minute of scheduled time for debugging
                            if abs(scheduled_hour - current_hour) == 0 and abs(scheduled_minute - current_minute) <= 1:
                                logger.info(f"   - ⚡ FORCING run due to close time match (within 1 minute)")
                                should_run = True

                    if not should_run:
                        logger.debug(f"Skipping report {report_config.id} - not scheduled for current time")
                        continue

                    # Check if we've already sent this report today to prevent duplicates
                    from models import SentAlert
                    today_key = f"report_{report_config.id}_{now_pakistan.strftime('%Y-%m-%d')}"
                    existing_report = SentAlert.query.filter(
                        SentAlert.alert_identifier == today_key,
                        SentAlert.timestamp >= now_pakistan.replace(hour=0, minute=0, second=0, microsecond=0)
                    ).first()

                    if existing_report:
                        logger.info(f"⏭️ Report {report_config.id} already sent today, skipping duplicate")
                        continue

                    logger.info(f"🚀 TRIGGERING scheduled report {report_config.id} ({report_config.name})")

                    # Generate the report
                    logger.info(f"📊 Generating report for config ID {report_config.id} ({report_config.name})")

                    # Set time range for the report (in UTC for data retrieval, but display times in PKT)
                    if report_config.schedule == 'daily':
                        start_time = (now_utc - timedelta(days=1)).isoformat()
                        period_desc = "last 24 hours"
                    elif report_config.schedule == 'weekly':
                        start_time = (now_utc - timedelta(days=7)).isoformat()
                        period_desc = "last 7 days"
                    elif report_config.schedule == 'monthly':
                        start_time = (now_utc - timedelta(days=30)).isoformat()
                        period_desc = "last 30 days"
                    else:
                        start_time = (now_utc - timedelta(days=1)).isoformat()
                        period_desc = "last 24 hours"

                    end_time = now_utc.isoformat()

                    logger.info(f"Report time range: {start_time} to {end_time} ({period_desc})")

                    # Generate report
                    try:
                        report = report_generator.generate_report(
                            report_config=report_config,
                            start_time=start_time,
                            end_time=end_time,
                            format=report_config.format,
                            timezone_offset=5  # Pakistan Standard Time offset
                        )

                        if not report:
                            logger.error(f"❌ Report generation failed for config {report_config.id}")
                            continue

                        logger.info(f"✅ Report generated successfully for config {report_config.id}")

                        # Record that we've sent this report to prevent duplicates
                        sent_report = SentAlert(
                            alert_config_id=report_config.id,
                            alert_identifier=today_key,
                            timestamp=now_pakistan
                        )
                        db.session.add(sent_report)
                        db.session.commit()

                    except Exception as e:
                        logger.error(f"❌ Exception during report generation for config {report_config.id}: {str(e)}")
                        continue

                    # Get recipients
                    try:
                        recipients = report_config.get_recipients()
                        if not recipients:
                            logger.error(f"❌ No recipients specified for report config {report_config.id}")
                            continue

                        logger.info(f"📧 Sending report to {len(recipients)} recipients: {recipients}")

                        # Convert UTC times to Pakistan time for display
                        start_pkt = (datetime.fromisoformat(start_time.replace('Z', '+00:00')) + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S')
                        end_pkt = (datetime.fromisoformat(end_time.replace('Z', '+00:00')) + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S')

                        subject = f"Security Report: {report_config.name} - {now_pakistan.strftime('%Y-%m-%d')} ({report_config.schedule})"

                        message = f"""
                        <html>
                        <head>
                            <style>
                                body {{ font-family: Arial, sans-serif; }}
                                .report-info {{ background-color: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; margin: 20px 0; }}
                            </style>
                        </head>
                        <body>
                            <h1>Scheduled Security Report</h1>
                            <div class="report-info">
                                <h3>Report Details</h3>
                                <p><strong>Report Name:</strong> {report_config.name}</p>
                                <p><strong>Schedule:</strong> {report_config.schedule.capitalize()}</p>
                                <p><strong>Period Covered:</strong> {period_desc}</p>
                                <p><strong>Data Range:</strong> {start_pkt} to {end_pkt} (PKT)</p>
                                <p><strong>Generated On:</strong> {now_pakistan.strftime('%Y-%m-%d %H:%M:%S')} PKT</p>
                                <p><strong>Severity Levels:</strong> {', '.join(report_config.get_severity_levels())}</p>
                            </div>
                            <p>Please find the detailed security report attached to this email.</p>
                            <p><strong>Note:</strong> All timestamps in the report are displayed in Pakistan Standard Time (PKT).</p>
                            <p>This is an automated email from AZ Sentinel X.</p>
                        </body>
                        </html>
                        """

                        # Prepare attachment
                        filename = f"security_report_{report_config.name.replace(' ', '_')}_{now_pakistan.strftime('%Y%m%d_%H%M')}"
                        attachments = None
                        
                        if report_config.format == 'pdf':
                            # Check if PDF is available
                            if report_generator.is_pdf_available():
                                mime_type = 'application/pdf'
                                filename += '.pdf'
                                attachments = [{
                                    'content': report,
                                    'filename': filename,
                                    'mime_type': mime_type
                                }]
                            else:
                                logger.warning(f"PDF requested but not available for report {report_config.id}, sending HTML inline")
                                message = report  # Send HTML content directly
                        else:
                            mime_type = 'text/html'
                            filename += '.html'
                            attachments = [{
                                'content': report.encode('utf-8') if isinstance(report, str) else report,
                                'filename': filename,
                                'mime_type': mime_type
                            }]

                        # Send to each recipient
                        send_success = True
                        for recipient in recipients:
                            try:
                                logger.info(f"📨 Sending email to {recipient}")
                                result = email_alerts.send_alert_email(
                                    recipient=recipient,
                                    subject=subject,
                                    message=message,
                                    attachments=attachments
                                )

                                if result:
                                    logger.info(f"✅ Successfully sent report to {recipient}")
                                else:
                                    logger.error(f"❌ Failed to send report to {recipient}")
                                    send_success = False

                            except Exception as e:
                                logger.error(f"❌ Exception sending email to {recipient}: {str(e)}")
                                send_success = False

                        if send_success:
                            logger.info(f"✅ Report successfully sent to all {len(recipients)} recipients")
                        else:
                            logger.warning(f"⚠️ Report sending had some failures for config {report_config.id}")

                    except Exception as e:
                        logger.error(f"❌ Exception getting recipients for report {report_config.id}: {str(e)}")

                except Exception as e:
                    logger.error(f"Error processing report config {report_config.id}: {str(e)}")

    except Exception as e:
        logger.error(f"Error in generate_and_send_reports job: {str(e)}")


def update_scheduler_jobs():
    """
    Update scheduler jobs based on system configuration
    """
    logger.info("Updating scheduler jobs")

    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return

    try:
        # Use the application context from the scheduler
        with scheduler.app.app_context():
            # Get alert check interval from system config or use default (2 minutes for immediate response)
            interval_value = SystemConfig.get_value('alert_check_interval', '2')
            alert_check_interval = 2  # Default fallback - more frequent checks for immediate alerts

            if interval_value:
                try:
                    alert_check_interval = int(interval_value)
                    # Ensure minimum 1 minute interval for immediate alerts
                    if alert_check_interval < 1:
                        alert_check_interval = 1
                except (ValueError, TypeError):
                    logger.warning(f"Invalid alert_check_interval value: {interval_value}, using default 2")
                    alert_check_interval = 2
            else:
                logger.warning("No alert_check_interval value found, using default 2")
                alert_check_interval = 2

            # Remove existing jobs (if any)
            try:
                scheduler.remove_job('check_alerts')
                logger.info("Removed existing check_alerts job")
            except Exception:
                pass  # Job might not exist yet

            try:
                scheduler.remove_job('generate_reports')
                logger.info("Removed existing generate_reports job")
            except Exception:
                pass  # Job might not exist yet

            # Add the alert check job
            scheduler.add_job(
                id='check_alerts',
                func=check_and_send_alerts,
                trigger='interval',
                minutes=alert_check_interval,
                replace_existing=True
            )

            # Add the report generation job 
            # This runs every minute to check if any reports need to be sent
            scheduler.add_job(
                id='generate_reports',
                func=generate_and_send_reports,
                trigger='interval',
                minutes=1,
                replace_existing=True
            )

            logger.info(f"Scheduler jobs updated. Alert check interval: {alert_check_interval} minutes")

    except Exception as e:
        logger.error(f"Error updating scheduler jobs: {str(e)}")

def check_alerts():
    """Check for alerts based on configured alert rules"""
    try:
        logger.info("🔍 Running scheduled alert checking job")

        # Get all enabled alert configurations
        alert_configs = AlertConfig.query.filter_by(enabled=True).all()
        logger.info(f"Found {len(alert_configs)} enabled alert configurations")

        if not alert_configs:
            logger.info("No enabled alert configurations found")
            return

        email_alerts = EmailAlerts()

        for config in alert_configs:
            try:
                logger.info(f"📧 Processing alert config {config.id}: {config.name}")
                logger.info(f"   - Email recipient: {config.email_recipient}")
                logger.info(f"   - Alert levels: {config.get_alert_levels()}")

                # Send severity-based alert
                result = email_alerts.send_severity_alert(config)

                if result:
                    logger.info(f"✅ Successfully processed alert config {config.id}")
                else:
                    logger.warning(f"⚠️ Failed to process alert config {config.id}")

            except Exception as e:
                logger.error(f"❌ Error processing alert config {config.id}: {str(e)}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")

    except Exception as e:
        logger.error(f"❌ Error in alert checking job: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

def init_app(app):
    """
    Initialize the scheduler with the Flask app
    """
    # Set up the APScheduler
    scheduler.init_app(app)
    scheduler.app = app

    # Start the scheduler
    scheduler.start()
    logger.info("APScheduler started")

    # Set up the initial jobs
    with app.app_context():
        # Create default system configuration values
        try:
            if not SystemConfig.get_value('alert_check_interval'):
                SystemConfig.set_value('alert_check_interval', '2', 'Interval in minutes for checking alerts')

            if not SystemConfig.get_value('report_generation_time'):
                SystemConfig.set_value('report_generation_time', '08:00', 'Default time for generating reports (HH:MM format)')

            if not SystemConfig.get_value('max_concurrent_jobs'):
                SystemConfig.set_value('max_concurrent_jobs', '5', 'Maximum number of concurrent scheduled jobs')
        except Exception as e:
            logger.warning(f"Could not access database during scheduler initialization: {e}")
            logger.info("Continuing with default configuration values")

        # Create default alert_check_interval if it doesn't exist
        try:
            if not SystemConfig.get_value('alert_check_interval'):
                SystemConfig.set_value(
                    'alert_check_interval',
                    '5',
                    'Interval in minutes between alert checks'
                )
                db.session.commit()
                logger.info("Created default alert_check_interval system config")

            # Create default alert_duplicate_window if it doesn't exist
            if not SystemConfig.get_value('alert_duplicate_window'):
                SystemConfig.set_value(
                    'alert_duplicate_window',
                    '2',
                    'Hours to prevent duplicate alert notifications'
                )
                db.session.commit()
                logger.info("Created default alert_duplicate_window system config")
        except Exception as config_error:
            logger.error(f"Error creating system config: {str(config_error)}")
            # Continue with defaults

        # Update the scheduler jobs
        update_scheduler_jobs()

        # Add alert checking job - check every 2 minutes for immediate alerts
        scheduler.add_job(
            func=check_alerts,
            trigger="interval",
            minutes=2,
            id='check_alerts',
            replace_existing=True,
            max_instances=1
        )
        
        # Add alert storage job - store alerts in database every 30 minutes for AI training
        scheduler.add_job(
            func=store_alerts_in_database,
            trigger="interval",
            minutes=30,
            id='store_alerts',
            replace_existing=True,
            max_instances=1
        )