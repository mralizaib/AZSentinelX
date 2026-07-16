import os
import logging
import json
import datetime
import base64
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
    HTML = None


def _get_logo_base64():
    """Load the ByteIT logo and return as a base64 data URI."""
    try:
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'css', 'byteit-logo.jpg')
        with open(logo_path, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('utf-8')
        return f"data:image/jpeg;base64,{encoded}"
    except Exception as e:
        logger.warning(f"Could not load logo: {e}")
        return ""


class ReportGenerator:
    def __init__(self):
        self.opensearch = OpenSearchAPI()
        self.env = Environment(loader=FileSystemLoader('templates/report_templates'))

    def generate_report(self, report_config, start_time=None, end_time=None,
                        format="pdf", timezone_offset=5, alerts_data=None,
                        downloaded_by=None, downloaded_at=None):
        """
        Generate a report based on configuration.

        Args:
            report_config: ReportConfig object or dict with report settings
            start_time: Override start time (ISO format)
            end_time: Override end time (ISO format)
            format: 'pdf' or 'html'
            timezone_offset: Timezone offset in hours for display (default: 5 for PKT)
            alerts_data: Optional pre-fetched alerts data
            downloaded_by: Username of the person requesting the report
            downloaded_at: Datetime string of when the report was requested

        Returns:
            BytesIO object with the report or HTML string
        """
        try:
            logger.info(f"Starting report generation - Format: {format}")

            if not end_time:
                end_time = datetime.datetime.utcnow().isoformat()
            if not start_time:
                start_time = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()

            logger.info(f"Report time range: {start_time} to {end_time}")

            if hasattr(report_config, 'get_severity_levels'):
                severity_levels = report_config.get_severity_levels()
            else:
                severity_levels = report_config.get('severity_levels', ['critical', 'high', 'medium', 'low'])

            logger.info(f"Report severity levels: {severity_levels}")

            if alerts_data is None:
                logger.info("Fetching alerts from OpenSearch...")
                alerts_data = self.opensearch.search_alerts(
                    severity_levels=severity_levels,
                    start_time=start_time,
                    end_time=end_time,
                    limit=1000
                )
            else:
                logger.info(f"Using provided alerts_data with {len(alerts_data.get('results', []))} alerts")

            if 'error' in alerts_data:
                logger.error(f"Error fetching alerts for report: {alerts_data['error']}")
                return None

            logger.info(f"Fetched {alerts_data.get('total', 0)} alerts")

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
        except Exception:
            start_pkt = start_time
            end_pkt = end_time

        # Convert alert timestamps and collect full logs
        pkt_alerts = []
        for alert in alerts_data.get('results', []):
            alert_copy = alert.copy()
            src = alert_copy.get('source', {})
            if '@timestamp' in src:
                try:
                    utc_time = datetime.datetime.fromisoformat(src['@timestamp'].replace('Z', '+00:00'))
                    pkt_time = utc_time + datetime.timedelta(hours=timezone_offset)
                    src['@timestamp'] = pkt_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    src['@timestamp_display'] = pkt_time.strftime('%Y-%m-%d %H:%M:%S PKT')
                except Exception:
                    src['@timestamp_display'] = src.get('@timestamp', 'N/A')

            # Build a clean full_log string — prefer full_log field, then data, then raw source
            full_log = src.get('full_log', '')
            if not full_log:
                data_field = src.get('data', {})
                if data_field:
                    try:
                        full_log = json.dumps(data_field, indent=2)
                    except Exception:
                        full_log = str(data_field)
            if not full_log:
                try:
                    full_log = json.dumps(src, indent=2)
                except Exception:
                    full_log = str(src)

            # Truncate at source to keep the template payload small
            if len(full_log) > 800:
                full_log = full_log[:800] + f'\n... [truncated — {len(full_log)} chars total]'

            alert_copy['full_log_text'] = full_log
            pkt_alerts.append(alert_copy)

        # Determine download metadata
        if downloaded_at is None:
            downloaded_at = now_pkt.strftime('%Y-%m-%d %H:%M:%S PKT')
        if downloaded_by is None:
            downloaded_by = 'System (Scheduled)'

        # Build severity breakdown for the chart
        severity_bar = {}
        total = alerts_data.get('total', 0) or 1
        for sev in ['critical', 'high', 'medium', 'low']:
            count = alert_counts.get(sev, 0) or 0
            severity_bar[sev] = {
                'count': count,
                'pct': round(count / total * 100) if total else 0,
            }

        report_data = {
            'title': f"Security Alert Report — {now_pkt.strftime('%Y-%m-%d')} PKT",
            'generated_at': now_pkt.strftime('%Y-%m-%d %H:%M:%S PKT'),
            'downloaded_by': downloaded_by,
            'downloaded_at': downloaded_at,
            'period': {'start': start_pkt, 'end': end_pkt},
            'alerts': pkt_alerts,
            'alert_counts': alert_counts,
            'severity_bar': severity_bar,
            'severity_levels': severity_levels,
            'total_alerts': alerts_data.get('total', 0),
            'timezone_note': 'All timestamps are in Pakistan Standard Time (PKT, UTC+5)',
            'logo_data_uri': _get_logo_base64(),
        }

        # Cap number of alerts in PDF to keep rendering fast
        if format.lower() == 'pdf' and len(report_data['alerts']) > 200:
            report_data['pdf_capped'] = True
            report_data['alerts'] = report_data['alerts'][:200]
        else:
            report_data['pdf_capped'] = False

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
            html_content = self._generate_html_report(report_data)
            pdf_file = BytesIO()
            HTML(string=html_content).write_pdf(pdf_file)
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
            raise NotImplementedError("PDF generation is not available. System dependencies are missing. Please use HTML format instead.")
        except ImportError:
            raise NotImplementedError("PDF generation is not available. System dependencies are missing. Please use HTML format instead.")
