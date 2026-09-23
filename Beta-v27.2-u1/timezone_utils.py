"""Timezone helpers shared by alert filtering, display, reports, and email."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from config import Config


UTC = timezone.utc


def get_server_timezone_name(server_key='primary'):
    """Return the configured IANA timezone name for a Wazuh server."""
    server = Config.get_server(server_key)
    return server.get('timezone') or 'UTC'


def get_server_timezone(server_key='primary'):
    """Return a valid ZoneInfo for a Wazuh server, falling back to UTC."""
    timezone_name = get_server_timezone_name(server_key)
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return UTC


def timezone_label(server_key='primary'):
    """Return a readable timezone label, including the IANA zone."""
    zone = get_server_timezone(server_key)
    zone_name = get_server_timezone_name(server_key)
    abbreviation = datetime.now(zone).tzname() or zone_name
    return f'{abbreviation} ({zone_name})'


def parse_alert_timestamp(value):
    """Parse an OpenSearch timestamp while preserving its original instant."""
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def format_timestamp_for_server(value, server_key='primary', include_zone=True,
                                include_seconds=True):
    """Format an alert timestamp in its originating server's local timezone."""
    if value in (None, '', 'N/A'):
        return 'N/A' if value in (None, '') else str(value)
    try:
        local_time = parse_alert_timestamp(value).astimezone(
            get_server_timezone(server_key)
        )
        pattern = '%Y-%m-%d %H:%M:%S' if include_seconds else '%Y-%m-%d %H:%M'
        formatted = local_time.strftime(pattern)
        if include_zone:
            formatted = f'{formatted} {local_time.tzname() or get_server_timezone_name(server_key)}'
        return formatted
    except (TypeError, ValueError, OverflowError):
        return str(value)


def localize_iso_range(value, server_key='primary'):
    """Convert an ISO timestamp to the selected server's timezone."""
    try:
        return parse_alert_timestamp(value).astimezone(get_server_timezone(server_key))
    except (TypeError, ValueError, OverflowError):
        return None