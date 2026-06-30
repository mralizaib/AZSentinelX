import logging
import os
import json
import threading
from flask import Blueprint, jsonify, request, render_template, send_file, abort
from flask_login import login_required, current_user
from opensearch_api import OpenSearchAPI
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
storage_bp = Blueprint('storage', __name__)

# Default backup directory (relative to this file → Beta-V22/backups/)
_DEFAULT_BACKUP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backups')

# In-memory progress tracker for running backup/restore jobs  {backup_id: docs_processed}
_job_progress = {}
_job_lock = threading.Lock()


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


# ═══════════════════════════════════════════════════════════════════
# Log Backup Endpoints
# ═══════════════════════════════════════════════════════════════════

def _fmt_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _serialize_backup(b):
    return {
        'id':            b.id,
        'name':          b.name,
        'log_type':      b.log_type,
        'months':        b.get_months(),
        'status':        b.status,
        'doc_count':     b.doc_count,
        'file_size':     _fmt_bytes(b.file_size_bytes) if b.file_size_bytes else '–',
        'file_path':     b.file_path,
        'file_exists':   b.file_exists(),
        'error_message': b.error_message,
        'notes':         b.notes,
        'created_at':    b.created_at.strftime('%Y-%m-%d %H:%M') if b.created_at else '',
        'completed_at':  b.completed_at.strftime('%Y-%m-%d %H:%M') if b.completed_at else '',
    }


@storage_bp.route('/api/storage/backups')
@login_required
def list_backups():
    """Return all backup records, newest first."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        from models import LogBackup
        backups = LogBackup.query.order_by(LogBackup.created_at.desc()).all()
        return jsonify([_serialize_backup(b) for b in backups])
    except Exception as e:
        logger.error(f"list_backups error: {e}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/backup', methods=['POST'])
@login_required
def create_backup():
    """
    Start a background export of selected OpenSearch indices to a compressed NDJSON archive.
    Body: { name, log_type, selected_months, save_path (optional), notes (optional) }
    """
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        from models import LogBackup, db
        data = request.json or {}
        name          = (data.get('name') or '').strip()
        log_type      = data.get('log_type', 'wazuh-alerts-*')
        selected_months = data.get('selected_months', [])
        save_path     = (data.get('save_path') or '').strip()
        notes         = (data.get('notes') or '').strip()

        if not name:
            ts = datetime.utcnow().strftime('%Y%m%d-%H%M')
            name = f"backup-{log_type.replace('*','').strip('-')}-{ts}"

        if not selected_months:
            return jsonify({'error': 'Select at least one month to back up.'}), 400

        # Resolve save directory
        save_dir = save_path if save_path else _DEFAULT_BACKUP_DIR
        try:
            os.makedirs(save_dir, exist_ok=True)
        except Exception as dir_err:
            return jsonify({'error': f'Cannot create save directory: {dir_err}'}), 400

        # Determine which indices to export
        opensearch = OpenSearchAPI()
        patterns = _get_patterns(log_type)
        indices_to_export = []
        month_set = set(selected_months)
        for pattern in patterns:
            all_indices = _safe_get_indices(opensearch, pattern)
            for idx in all_indices:
                try:
                    date_str  = idx['index'].split('-')[-1]
                    idx_date  = datetime.strptime(date_str, '%Y.%m.%d').date()
                    month_key = idx_date.strftime('%Y.%m')
                    if month_key in month_set:
                        indices_to_export.append(idx['index'])
                except Exception:
                    continue

        if not indices_to_export:
            return jsonify({'error': 'No matching indices found for the selected months.'}), 400

        # Build file path
        safe_name = "".join(c if c.isalnum() or c in '-_.' else '_' for c in name)
        ts_str    = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename  = f"{safe_name}_{ts_str}.ndjson.gz"
        file_path = os.path.join(save_dir, filename)

        # Create DB record
        backup = LogBackup(
            name=name,
            log_type=log_type,
            months=json.dumps(sorted(selected_months)),
            indices=json.dumps(sorted(indices_to_export)),
            file_path=file_path,
            status='running',
            notes=notes,
            created_by=current_user.id,
        )
        db.session.add(backup)
        db.session.commit()
        backup_id = backup.id

        # Launch background export thread
        from app import app as _app
        def _run_backup():
            with _app.app_context():
                from models import LogBackup as _LB, db as _db
                rec = _LB.query.get(backup_id)
                if not rec:
                    return
                try:
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    api = OpenSearchAPI()

                    def _progress(n):
                        with _job_lock:
                            _job_progress[backup_id] = n

                    doc_count = api.export_indices_to_ndjson(
                        indices_to_export, file_path, progress_cb=_progress
                    )
                    size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    rec.status          = 'complete'
                    rec.doc_count       = doc_count
                    rec.file_size_bytes = size
                    rec.completed_at    = datetime.utcnow()
                    logger.info(f"Backup {backup_id} '{name}' complete — {doc_count} docs, {size} bytes")
                except Exception as err:
                    rec.status        = 'failed'
                    rec.error_message = str(err)
                    logger.error(f"Backup {backup_id} failed: {err}")
                finally:
                    _db.session.commit()
                    with _job_lock:
                        _job_progress.pop(backup_id, None)

        t = threading.Thread(target=_run_backup, daemon=True)
        t.start()

        return jsonify({'success': True, 'backup_id': backup_id,
                        'message': f'Backup started — {len(indices_to_export)} indices queued.'})
    except Exception as e:
        logger.error(f"create_backup error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/backup/<int:backup_id>/status')
@login_required
def backup_status(backup_id):
    """Poll status of a backup or restore job."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        from models import LogBackup
        b = LogBackup.query.get_or_404(backup_id)
        with _job_lock:
            progress = _job_progress.get(backup_id, None)
        result = _serialize_backup(b)
        result['progress_docs'] = progress
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/backup/<int:backup_id>/download')
@login_required
def download_backup(backup_id):
    """Stream the backup file to the browser."""
    if not current_user.is_admin():
        abort(403)
    from models import LogBackup
    b = LogBackup.query.get_or_404(backup_id)
    if b.status != 'complete' or not b.file_exists():
        abort(404)
    return send_file(
        b.file_path,
        as_attachment=True,
        download_name=os.path.basename(b.file_path),
        mimetype='application/gzip',
    )


@storage_bp.route('/api/storage/backup/<int:backup_id>/restore', methods=['POST'])
@login_required
def restore_backup(backup_id):
    """Re-index the backup archive back into OpenSearch."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        from models import LogBackup, db
        b = LogBackup.query.get_or_404(backup_id)
        if not b.file_exists():
            return jsonify({'error': 'Backup file not found on disk.'}), 404
        if b.status not in ('complete', 'failed', 'restored'):
            return jsonify({'error': f'Cannot restore a backup in status: {b.status}'}), 400

        b.status = 'restoring'
        db.session.commit()

        from app import app as _app
        bid = backup_id
        fpath = b.file_path

        def _run_restore():
            with _app.app_context():
                from models import LogBackup as _LB, db as _db
                rec = _LB.query.get(bid)
                if not rec:
                    return
                try:
                    api = OpenSearchAPI()
                    def _progress(n):
                        with _job_lock:
                            _job_progress[bid] = n
                    success, failed = api.restore_ndjson_to_opensearch(fpath, progress_cb=_progress)
                    rec.status       = 'restored'
                    rec.completed_at = datetime.utcnow()
                    logger.info(f"Restore {bid} complete — {success} docs indexed, {failed} failed")
                except Exception as err:
                    rec.status        = 'failed'
                    rec.error_message = f'Restore error: {err}'
                    logger.error(f"Restore {bid} failed: {err}")
                finally:
                    _db.session.commit()
                    with _job_lock:
                        _job_progress.pop(bid, None)

        threading.Thread(target=_run_restore, daemon=True).start()
        return jsonify({'success': True, 'message': 'Restore started in background.'})
    except Exception as e:
        logger.error(f"restore_backup error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/backup/<int:backup_id>', methods=['DELETE'])
@login_required
def delete_backup(backup_id):
    """Delete backup DB record and optionally the archive file."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        from models import LogBackup, db
        b = LogBackup.query.get_or_404(backup_id)
        delete_file = request.json.get('delete_file', True) if request.json else True
        file_deleted = False
        if delete_file and b.file_path and os.path.exists(b.file_path):
            try:
                os.remove(b.file_path)
                file_deleted = True
            except Exception as fe:
                logger.warning(f"Could not delete backup file {b.file_path}: {fe}")
        db.session.delete(b)
        db.session.commit()
        return jsonify({'success': True, 'file_deleted': file_deleted})
    except Exception as e:
        logger.error(f"delete_backup error: {e}")
        return jsonify({'error': str(e)}), 500


@storage_bp.route('/api/storage/backup/available-months', methods=['POST'])
@login_required
def backup_available_months():
    """Return all months available for backup (no protection restriction)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        data = request.json or {}
        log_type = data.get('log_type', 'wazuh-alerts-*')
        opensearch = OpenSearchAPI()
        months = {}
        for p in _get_patterns(log_type):
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
                        }
                    months[month_key]['count'] += 1
                    months[month_key]['size_bytes'] += _parse_size(idx.get('pri.store.size', '0b'))
                except Exception:
                    continue
        result = sorted(months.values(), key=lambda x: x['month'])
        for m in result:
            m['size'] = _format_size(m['size_bytes'])
            del m['size_bytes']
        return jsonify({'months': result})
    except Exception as e:
        logger.error(f"backup_available_months error: {e}")
        return jsonify({'error': str(e)}), 500
