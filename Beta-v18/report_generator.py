import os
import logging
import json
import datetime
from jinja2 import Environment, FileSystemLoader
from io import BytesIO
from flask import render_template_string
from opensearch_api import OpenSearchAPI
from config import Config

logger = logging.getLogger(__name__)

# Try to import WeasyPrint, fall back to HTML-only mode if not available
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as e:
    logger.warning(f"WeasyPrint not available: {e}. PDF generation will be disabled.")
    WEASYPRINT_AVAILABLE = False
    HTML = None  # Set to None so we can check for it later

class ReportGenerator:
    def __init__(self):
        self.opensearch = OpenSearchAPI()
        self.env = Environment(loader=FileSystemLoader('templates/report_templates'))

    def generate_report(self, report_config, start_time=None, end_time=None, format="pdf", timezone_offset=5, alerts_data=None):
        """
        Generate a report based on configuration

        Args:
            report_config: ReportConfig object or dict with report settings
            start_time: Override start time (ISO format)
            end_time: Override end time (ISO format)
            format: 'pdf' or 'html'
            timezone_offset: Timezone offset in hours for display (default: 5 for PKT)
            alerts_data: Optional pre-fetched alerts data

        Returns:
            BytesIO object with the report or HTML string
        """
        try:
            logger.info(f"Starting report generation - Format: {format}")

            # Set default time range if not provided
            if not end_time:
                end_time = datetime.datetime.utcnow().isoformat()

            if not start_time:
                # Default to 24 hours if not specified
                start_time = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()

            logger.info(f"Report time range: {start_time} to {end_time}")

            # Get severity levels from config
            if hasattr(report_config, 'get_severity_levels'):
                severity_levels = report_config.get_severity_levels()
            else:
                severity_levels = report_config.get('severity_levels', ['critical', 'high', 'medium', 'low'])

            logger.info(f"Report severity levels: {severity_levels}")

            # Use provided alerts_data if available, otherwise fetch fresh data
            if alerts_data is None:
                # Fetch alerts from OpenSearch
                logger.info("Fetching alerts from OpenSearch...")
                alerts_data = self.opensearch.search_alerts(
                    severity_levels=severity_levels,
                    start_time=start_time,
                    end_time=end_time,
                    limit=1000  # Increase limit for reports
                )
            else:
                logger.info(f"Using provided alerts_data with {len(alerts_data.get('results', []))} alerts")


            if 'error' in alerts_data:
                logger.error(f"Error fetching alerts for report: {alerts_data['error']}")
                return None

            logger.info(f"Fetched {alerts_data.get('total', 0)} alerts")

            # Get alert count by severity
            logger.info("Getting alert counts by severity...")
            alert_counts = self.opensearch.get_alert_count_by_severity(
                start_time=start_time,
                end_time=end_time
            )

            logger.info(f"Alert counts: {alert_counts}")
        except Exception as e:
            logger.error(f"Error during data fetching for report: {str(e)}")
            return None

        # Convert timestamps to Pakistan time for display
        now_pkt = datetime.datetime.now() + datetime.timedelta(hours=timezone_offset)
        try:
            start_pkt = (datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00')) + datetime.timedelta(hours=timezone_offset)).strftime('%Y-%m-%d %H:%M:%S')
            end_pkt = (datetime.datetime.fromisoformat(end_time.replace('Z', '+00:00')) + datetime.timedelta(hours=timezone_offset)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            start_pkt = start_time
            end_pkt = end_time

        # Convert alert timestamps to Pakistan time
        pkt_alerts = []
        for alert in alerts_data.get('results', []):
            alert_copy = alert.copy()
            if 'source' in alert_copy and '@timestamp' in alert_copy['source']:
                try:
                    utc_time = datetime.datetime.fromisoformat(alert_copy['source']['@timestamp'].replace('Z', '+00:00'))
                    pkt_time = utc_time + datetime.timedelta(hours=timezone_offset)
                    alert_copy['source']['@timestamp'] = pkt_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    alert_copy['source']['@timestamp_display'] = pkt_time.strftime('%Y-%m-%d %H:%M:%S PKT')
                except:
                    alert_copy['source']['@timestamp_display'] = alert_copy['source'].get('@timestamp', 'N/A')
            pkt_alerts.append(alert_copy)

        # Prepare data for the report
        report_data = {
            'title': f"Security Alert Report - {now_pkt.strftime('%Y-%m-%d %H:%M')} PKT",
            'generated_at': now_pkt.strftime('%Y-%m-%d %H:%M:%S PKT'),
            'period': {
                'start': start_pkt,
                'end': end_pkt
            },
            'alerts': pkt_alerts,
            'alert_counts': alert_counts,
            'severity_levels': severity_levels,
            'total_alerts': alerts_data.get('total', 0),
            'timezone_note': 'All timestamps are displayed in Pakistan Standard Time (PKT)'
        }

        # Generate the report in requested format
        if format.lower() == 'pdf':
            return self._generate_pdf_report(report_data)
        else:
            return self._generate_html_report(report_data)

    def _generate_html_report(self, report_data):
        """Generate HTML report"""
        try:
            template = self.env.get_template('html_report.html')
            html_content = template.render(**report_data)
            return html_content
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            return f"<h1>Error generating report</h1><p>{str(e)}</p>"

    def _generate_pdf_report(self, report_data):
        """Generate PDF report"""
        if not WEASYPRINT_AVAILABLE or HTML is None:
            logger.error("WeasyPrint is not available. Cannot generate PDF reports.")
            return None

        try:
            # Get HTML content first
            html_content = self._generate_html_report(report_data)

            # Convert HTML to PDF
            pdf_file = BytesIO()
            HTML(string=html_content).write_pdf(pdf_file)

            # Reset file pointer to beginning
            pdf_file.seek(0)

            return pdf_file
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            return None

    def is_pdf_available(self):
        """Check if PDF generation is available"""
        return WEASYPRINT_AVAILABLE

    def generate_pdf_report(self, alerts_data, filters):
        """Generate PDF report with proper error handling"""
        try:
            import reportlab
            # If reportlab is available, implement PDF generation
            # For now, raise a more user-friendly error
            raise NotImplementedError("PDF generation is not available. System dependencies are missing. Please use HTML format instead.")
        except ImportError:
            raise NotImplementedError("PDF generation is not available. System dependencies are missing. Please use HTML format instead.")