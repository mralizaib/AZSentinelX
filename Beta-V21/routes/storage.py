import logging
import os
from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from opensearch_api import OpenSearchAPI
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
storage_bp = Blueprint('storage', __name__)


@storage_bp.route('/storage')
@login_required
def index():
    if not current_user.is_admin():
        return "Unauthorized", 403
    return render_template('storage.html')


@storage_bp.route('/api/storage/wazuh-disk-usage')
@login_required
def get_wazuh_disk_usage():
    """Get actual disk usage from the Wazuh/OpenSearch server nodes"""
    try:
        opensearch = OpenSearchAPI()
        stats = opensearch.get_node_disk_stats()
        if 'error' in stats:
            return jsonify({'error': stats['error']}), 502
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting Wazuh disk usage: {str(e)}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/indices')
@login_required
def get_indices():
    """Get list of OpenSearch indices related to Wazuh"""
    try:
        opensearch = OpenSearchAPI()
        indices = opensearch.get_indices("wazuh-*")
        return jsonify(indices)
    except Exception as e:
        logger.error(f"Error getting indices: {str(e)}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/trend')
@login_required
def storage_trend():
    """
    Return month-by-month index sizes for archives and alerts.
    Response: { months: ['2025.10', ...], archives: [gb, ...], alerts: [gb, ...] }
    """
    try:
        opensearch = OpenSearchAPI()
        months = {}   # month_key -> {'archives': bytes, 'alerts': bytes}

        for pattern, bucket in [('wazuh-archives-*', 'archives'), ('wazuh-alerts-*', 'alerts')]:
            indices = _safe_get_indices(opensearch, pattern)
            for idx in indices:
                try:
                    date_str = idx['index'].split('-')[-1]
                    idx_date = datetime.strptime(date_str, '%Y.%m.%d').date()
                    month_key = idx_date.strftime('%Y.%m')
                    if month_key not in months:
                        months[month_key] = {'archives': 0, 'alerts': 0, 'label': idx_date.strftime('%b %Y')}
                    months[month_key][bucket] += _parse_size(idx.get('pri.store.size', '0b'))
                except Exception:
                    continue

        # Sort chronologically
        sorted_months = sorted(months.items())
        min_allowed = _min_allowed_date().strftime('%Y.%m')

        # Decide unit: use MB when all values fit within 10 GB to keep chart readable
        all_bytes = [v['archives'] + v['alerts'] for _, v in sorted_months]
        max_bytes = max(all_bytes) if all_bytes else 0
        if max_bytes >= 1024 ** 3:
            divisor = 1024 ** 3
            unit = 'GB'
        else:
            divisor = 1024 ** 2
            unit = 'MB'

        result = {
            'months':   [k for k, _ in sorted_months],
            'labels':   [v['label'] for _, v in sorted_months],
            'archives': [round(v['archives'] / divisor, 2) for _, v in sorted_months],
            'alerts':   [round(v['alerts'] / divisor, 2) for _, v in sorted_months],
            'protected_from': min_allowed,
            'unit': unit,
        }
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error building storage trend: {str(e)}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/indices/<name>', methods=['DELETE'])
@login_required
def delete_index(name):
    """Delete a specific index"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        opensearch = OpenSearchAPI()
        result = opensearch.delete_index(name)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error deleting index {name}: {str(e)}")
        return jsonify({'error': str(e)}), 500


def _min_allowed_date():
    """Return the oldest date within the protected 3-month window (date object, UTC)."""
    return (datetime.utcnow() - timedelta(days=90)).date()


def _parse_size(size_str):
    if not size_str:
        return 0
    units = {"kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4, "b": 1}
    size_str = size_str.lower().strip()
    for unit, multiplier in units.items():
        if size_str.endswith(unit):
            try:
                return float(size_str.replace(unit, "").strip()) * multiplier
            except Exception:
                return 0
    return 0


def _format_size(bytes_val):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"


def _get_patterns(pattern):
    return ['wazuh-archives-*', 'wazuh-alerts-*'] if pattern == 'all' else [pattern]


def _safe_get_indices(opensearch, pattern):
    """
    Call opensearch.get_indices() and always return a list.
    If the call fails or returns an error dict, log and return [].
    """
    result = opensearch.get_indices(pattern)
    if isinstance(result, dict):
        if 'error' in result:
            logger.warning(f"get_indices({pattern}) returned error: {result['error']}")
        return []
    return result if isinstance(result, list) else []


@storage_bp.route('/api/storage/cleanup/available-months', methods=['POST'])
@login_required
def cleanup_available_months():
    """
    Return all available months that have log indices, grouped by YYYY.MM.
    Each month includes count, total size, and whether it is protected (last 90 days).
    """
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        data = request.json or {}
        pattern = data.get('pattern', 'wazuh-alerts-*')
        opensearch = OpenSearchAPI()
        months = {}

        # A month is protected if ANY day in it falls within the 90-day retention window.
        # We compare the month key string (YYYY.MM) directly against min_allowed_month.
        # Any month >= min_allowed_month contains protected days and must not be deleted.
        min_allowed_month = _min_allowed_date().strftime('%Y.%m')

        for p in _get_patterns(pattern):
            indices = _safe_get_indices(opensearch, p)
            for idx in indices:
                try:
                    date_str = idx['index'].split('-')[-1]
                    idx_date = datetime.strptime(date_str, '%Y.%m.%d').date()
                    month_key = idx_date.strftime('%Y.%m')
                    if month_key not in months:
                        months[month_key] = {
                            'month': month_key,
                            'label': idx_date.strftime('%B %Y'),
                            'count': 0,
                            'size_bytes': 0,
                            'protected': month_key >= min_allowed_month,
                        }
                    months[month_key]['count'] += 1
                    months[month_key]['size_bytes'] += _parse_size(idx.get('pri.store.size', '0b'))
                except Exception:
                    continue

        result = sorted(months.values(), key=lambda x: x['month'])
        for m in result:
            m['size'] = _format_size(m['size_bytes'])
            del m['size_bytes']

        return jsonify({'months': result, 'min_allowed': min_allowed_month})
    except Exception as e:
        logger.error(f"Error fetching available months: {str(e)}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/cleanup/preview', methods=['POST'])
@login_required
def cleanup_preview():
    """Preview which indices would be deleted and how much space would be freed"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        data = request.json
        pattern = data.get('pattern', 'wazuh-alerts-*')
        selected_months = set(data.get('selected_months', []))
        opensearch = OpenSearchAPI()
        min_allowed = _min_allowed_date()

        if not selected_months:
            return jsonify({'error': 'No months selected. Please choose at least one month to preview.'}), 400

        to_delete = []
        total_size_bytes = 0

        override_protection = data.get('override_protection', False)

        for p in _get_patterns(pattern):
            indices = _safe_get_indices(opensearch, p)
            for idx in indices:
                try:
                    date_str = idx['index'].split('-')[-1]
                    idx_date = datetime.strptime(date_str, '%Y.%m.%d').date()
                    month_key = idx_date.strftime('%Y.%m')
                    if month_key not in selected_months:
                        continue
                    # Skip protected dates unless user explicitly overrides
                    is_protected = idx_date > min_allowed
                    if is_protected and not override_protection:
                        continue
                    size_bytes = _parse_size(idx.get('pri.store.size', '0b'))
                    to_delete.append({
                        'index': idx['index'],
                        'size': idx.get('pri.store.size', '0 B'),
                        'date': date_str,
                        'month': month_key,
                        'protected': is_protected,
                    })
                    total_size_bytes += size_bytes
                except Exception:
                    continue

        # Sort preview by index name (date order)
        to_delete.sort(key=lambda x: x['index'])

        has_protected = any(i['protected'] for i in to_delete)
        months_label = ', '.join(sorted(selected_months))
        return jsonify({
            'indices': to_delete,
            'total_count': len(to_delete),
            'total_size': _format_size(total_size_bytes),
            'months_label': months_label,
            'has_protected': has_protected,
        })
    except Exception as e:
        logger.error(f"Error in cleanup preview: {str(e)}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/cleanup', methods=['POST'])
@login_required
def cleanup_indices():
    """Delete log indices for the selected months"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        data = request.json
        pattern = data.get('pattern', 'wazuh-alerts-*')
        selected_months = set(data.get('selected_months', []))
        opensearch = OpenSearchAPI()
        min_allowed = _min_allowed_date()

        if not selected_months:
            return jsonify({'error': 'No months selected.'}), 400

        override_protection = data.get('override_protection', False)

        deleted_count = 0
        for p in _get_patterns(pattern):
            indices = _safe_get_indices(opensearch, p)
            for idx in indices:
                index_name = idx['index']
                try:
                    date_str = index_name.split('-')[-1]
                    idx_date = datetime.strptime(date_str, '%Y.%m.%d').date()
                    month_key = idx_date.strftime('%Y.%m')
                    if month_key not in selected_months:
                        continue
                    if idx_date > min_allowed and not override_protection:
                        continue
                    opensearch.delete_index(index_name)
                    deleted_count += 1
                    logger.info(f"Deleted index: {index_name} (override={override_protection})")
                except (ValueError, IndexError):
                    continue

        months_label = ', '.join(sorted(selected_months))
        return jsonify({
            'success': True,
            'message': f'Removed {deleted_count} log indices for {months_label}'
        })
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        return jsonify({'error': str(e)}), 500
