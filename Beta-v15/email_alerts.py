import os
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

class EmailAlerts:
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_username = Config.SMTP_USERNAME
        self.smtp_password = Config.SMTP_PASSWORD
        self.smtp_use_tls = Config.SMTP_USE_TLS
        self.opensearch = OpenSearchAPI()
        self.report_generator = ReportGenerator()
        
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
            Boolean indicating success or failure
        """
        if not self.smtp_username or not self.smtp_password:
            logger.error("SMTP credentials not configured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            # Set sender name to "Wazuh" with the SMTP username as the email address
            msg['From'] = f"Wazuh <{self.smtp_username}>"
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
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                    server.set_debuglevel(1)  # Enable SMTP debugging
                    
                    if self.smtp_use_tls:
                        logger.info("📧 Starting TLS connection")
                        server.starttls()
                    
                    logger.info(f"📧 Logging in with username: {self.smtp_username}")
                    server.login(self.smtp_username, self.smtp_password)
                    
                    logger.info("📧 Sending message")
                    send_result = server.send_message(msg)
                    
                    if send_result:
                        logger.warning(f"📧 Some recipients failed: {send_result}")
                    else:
                        logger.info("📧 Message sent to all recipients successfully")
                
                logger.info(f"✅ Alert email successfully sent to {recipient}")
                return True
            except smtplib.SMTPAuthenticationError as auth_error:
                logger.error(f"❌ SMTP Authentication failed: {str(auth_error)}")
                return False
            except smtplib.SMTPRecipientsRefused as recip_error:
                logger.error(f"❌ SMTP Recipients refused: {str(recip_error)}")
                return False
            except smtplib.SMTPServerDisconnected as disconnect_error:
                logger.error(f"❌ SMTP Server disconnected: {str(disconnect_error)}")
                return False
            except Exception as smtp_error:
                logger.error(f"❌ SMTP Error: {str(smtp_error)}")
                return False
        except Exception as e:
            logger.error(f"Failed to send alert email: {str(e)}")
            return False
    
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
            Boolean indicating success or failure
        """
        try:
            # Get severity levels from config
            if hasattr(alert_config, 'get_alert_levels'):
                severity_levels = alert_config.get_alert_levels()
            else:
                severity_levels = alert_config.get('alert_levels', ['critical', 'high'])
            
            recipient = alert_config.email_recipient if hasattr(alert_config, 'email_recipient') else alert_config.get('email_recipient')
            
            if not recipient:
                logger.error("No recipient specified for alert")
                return False
            
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
                logger.error(f"Error fetching alerts for email: {alerts_data['error']}")
                return False
            
            # Check if there are any alerts to send
            total_alerts_found = len(alerts_data.get('results', []))
            logger.info(f"Found {total_alerts_found} alerts for levels: {', '.join(severity_levels)}")
            
            if total_alerts_found == 0 and not alerts_data.get('manual_test', False):
                logger.info(f"No alerts to send for levels: {', '.join(severity_levels)}")
                return True  # Return success as there's nothing to send
                
            # If this is a manual test with no alerts, create a test message
            if alerts_data.get('manual_test', False) and not alerts_data.get('results', []):
                logger.info("Creating test alert email for manual trigger")
                subject = f"WAZUH Security Alert: Test Alert (Manual)"
                message = f"""
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; }}
                        .alert-summary {{ margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 5px solid #28a745; }}
                    </style>
                </head>
                <body>
                    <h1>Test Security Alert</h1>
                    <div class="alert-summary">
                        <p>This is a test alert triggered manually from the Scheduler Management interface.</p>
                        <p>No actual alerts were found matching your configuration criteria.</p>
                        <p>Alert levels: {', '.join(severity_levels)}</p>
                        <p>Search time range: {(current_time_pkt - datetime.timedelta(minutes=alert_check_interval)).strftime('%Y-%m-%d %H:%M:%S')} to {current_time_pkt.strftime('%Y-%m-%d %H:%M:%S')} (PKT)</p>
                    </div>
                    <p>This email confirms that your alert notification system is working correctly.</p>
                </body>
                </html>
                """
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
            
            # Generate report as attachment with all alert data
            report_config = {
                'severity_levels': severity_levels,
                'include_fields': include_fields
            }
            
            # Pass the actual alerts data to ensure report contains current alerts
            try:
                report = self.report_generator.generate_report(
                    report_config, 
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
            
            # Build email subject
            total_alerts = alerts_data.get('total', 0)
            subject = f"Security Alert: {total_alerts} new alerts detected"
            
            # Get the include_fields if available
            include_fields = []
            if hasattr(alert_config, 'get_include_fields') and callable(getattr(alert_config, 'get_include_fields')):
                include_fields = alert_config.get_include_fields()
            else:
                include_fields = ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"]
            
            # Build email body
            body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .alert-summary {{ margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 5px solid #dc3545; }}
                    .alert-count {{ font-weight: bold; color: #dc3545; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                    .critical {{ color: #dc3545; font-weight: bold; }}
                    .high {{ color: #fd7e14; font-weight: bold; }}
                    .medium {{ color: #ffc107; }}
                    .low {{ color: #6c757d; }}
                    .table-container {{ margin-top: 20px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Security Alert Notification</h1>
                
                <div class="alert-summary">
                    <p>A total of <span class="alert-count">{total_alerts}</span> alerts have been detected in the last {alert_check_interval} minutes matching your alert configuration.</p>
                    <p>Alert levels: {', '.join(severity_levels)}</p>
                    <p>Time range: {(current_time_pkt - datetime.timedelta(minutes=alert_check_interval)).strftime('%Y-%m-%d %H:%M:%S')} to {current_time_pkt.strftime('%Y-%m-%d %H:%M:%S')} (PKT)</p>
                    <p>Generated at: {current_time_pkt.strftime('%Y-%m-%d %H:%M:%S')} PKT</p>
                </div>
                
                <h2>Alert Summary by Severity</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
            """
            
            # Add count rows
            for severity, count in alert_counts.items():
                if severity == "none" or count == 0:
                    continue
                body += f"""
                    <tr>
                        <td class="{severity}">{severity.capitalize()}</td>
                        <td>{count}</td>
                    </tr>
                """
            
            body += """
                </table>
                
                <h2>Recent Security Alerts</h2>
                <div class="table-container">
                <table>
                    <tr>
            """
            
            # Create table headers based on include_fields
            field_headers = {
                "@timestamp": "Timestamp",
                "agent.ip": "Agent IP",
                "agent.labels.location.set": "Location",
                "agent.name": "Agent Name",
                "rule.description": "Description",
                "rule.id": "Rule ID",
                "rule.level": "Severity Level",
                "decoder.name": "Decoder",
                "full_log": "Full Log"
            }
            
            # Add headers for each included field
            for field in include_fields:
                header = field_headers.get(field, field.split('.')[-1].capitalize())
                body += f"<th>{header}</th>"
            
            body += "</tr>"
            
            # Add recent alerts with the specified fields (show first 60 in email)
            for alert in alerts_data.get('results', [])[:60]:  # Show more alerts in email
                source = alert.get('source', {})
                
                # Determine severity level
                level = source.get('rule', {}).get('level', 0)
                severity_class = "low"
                if level >= 15:
                    severity_class = "critical"
                elif level >= 12:
                    severity_class = "high"
                elif level >= 7:
                    severity_class = "medium"
                
                body += f'<tr class="{severity_class}">'
                
                # Add data for each field
                for field in include_fields:
                    value = "N/A"
                    
                    # Handle nested fields with dot notation
                    if '.' in field:
                        parts = field.split('.')
                        current = source.copy()
                        
                        # Special handling for agent.labels.location.set
                        if field == "agent.labels.location.set":
                            if 'agent' in current and 'labels' in current['agent'] and 'location' in current['agent']['labels']:
                                value = current['agent']['labels']['location'].get('set', 'N/A')
                        else:
                            # General handling for nested fields
                            for part in parts:
                                if isinstance(current, dict) and part in current:
                                    current = current.get(part)
                                else:
                                    current = "N/A"
                                    break
                            
                            if current not in ["N/A", None]:
                                value = current
                    else:
                        value = source.get(field, "N/A")
                    
                    # Special formatting for agent.name to include IP
                    if field == "agent.name" and value != "N/A":
                        agent_ip = source.get('agent', {}).get('ip', 'N/A')
                        if agent_ip != 'N/A':
                            value = f"{value} ({agent_ip})"
                    
                    # Format timestamp nicely if it's a timestamp field
                    if field == "@timestamp" and value != "N/A" and isinstance(value, str):
                        try:
                            # Convert UTC timestamp to Pakistan time
                            if 'T' in value:
                                utc_time = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                                pkt_time = utc_time + datetime.timedelta(hours=5)
                                value = pkt_time.strftime('%Y-%m-%d %H:%M:%S PKT')
                        except Exception:
                            # If formatting fails, just use the original value
                            pass
                    
                    # Truncate very long values
                    if isinstance(value, str) and len(value) > 100:
                        value = value[:97] + "..."
                    
                    body += f"<td>{value}</td>"
                
                body += "</tr>"
            
            body += """
                </table>
                </div>
                
                <p>This is an automated alert from AZ Sentinel X. A detailed report is attached.</p>
            </body>
            </html>
            """
            
            # Prepare attachment if report was generated
            attachments = None
            if report:
                try:
                    # Handle both BytesIO (PDF) and string (HTML) report types
                    if hasattr(report, 'read'):
                        # It's a BytesIO object (PDF)
                        attachments = [{
                            'content': report,
                            'filename': f"security_alert_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                            'mime_type': 'application/pdf'
                        }]
                    elif isinstance(report, str):
                        # It's an HTML string
                        from io import BytesIO
                        html_bytes = BytesIO(report.encode('utf-8'))
                        attachments = [{
                            'content': html_bytes,
                            'filename': f"security_alert_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            'mime_type': 'text/html'
                        }]
                    else:
                        logger.warning("Report format not recognized, skipping attachment")
                except Exception as attach_error:
                    logger.error(f"Error preparing report attachment: {str(attach_error)}")
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
