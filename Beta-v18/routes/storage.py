import logging
import shutil
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

@storage_bp.route('/api/storage/disk-usage')
@login_required
def get_disk_usage():
    """Get disk usage of the server"""
    try:
        # On-premise Ubuntu path for Wazuh logs is typically /var/ossec
        # But we'll monitor the root partition where logs usually reside
        path = "/"
        try:
            stat = shutil.disk_usage(path)
        except:
            # Fallback if path doesn't exist
            return jsonify({
                'total': '0 B',
                'used': '0 B',
                'free': '0 B',
                'percent': 0
            })
        
        def format_size(bytes):
            if bytes < 1024:
                return f"{bytes:.2f} B"
            elif bytes < 1024**2:
                return f"{bytes/1024:.2f} KB"
            elif bytes < 1024**3:
                return f"{bytes/1024**2:.2f} MB"
            elif bytes < 1024**4:
                return f"{bytes/1024**3:.2f} GB"
            else:
                return f"{bytes/1024**4:.2f} TB"
        
        return jsonify({
            'total': format_size(stat.total),
            'used': format_size(stat.used),
            'free': format_size(stat.free),
            'percent': round((stat.used / stat.total) * 100, 2)
        })
    except Exception as e:
        logger.error(f"Error getting disk usage: {str(e)}")
        return jsonify({'error': str(e)}), 500

@storage_bp.route('/api/storage/indices')
@login_required
def get_indices():
    """Get list of OpenSearch indices related to Wazuh"""
    try:
        opensearch = OpenSearchAPI()
        # Fetch indices starting with wazuh-
        indices = opensearch.get_indices("wazuh-*")
        return jsonify(indices)
    except Exception as e:
        logger.error(f"Error getting indices: {str(e)}")
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

@storage_bp.route('/api/storage/cleanup/preview', methods=['POST'])
@login_required
def cleanup_preview():
    """Preview which indices would be deleted and how much space would be freed"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        pattern = data.get('pattern', 'wazuh-archives-*')
        days = int(data.get('days', 30))
        
        opensearch = OpenSearchAPI()
        patterns = ['wazuh-archives-*', 'wazuh-alerts-*'] if pattern == 'all' else [pattern]
        
        to_delete = []
        total_size_bytes = 0
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        def parse_size(size_str):
            if not size_str: return 0
            units = {"kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4, "b": 1}
            size_str = size_str.lower().strip()
            for unit, multiplier in units.items():
                if size_str.endswith(unit):
                    try:
                        return float(size_str.replace(unit, "").strip()) * multiplier
                    except:
                        return 0
            return 0

        for p in patterns:
            indices = opensearch.get_indices(p)
            for idx in indices:
                try:
                    date_str = idx['index'].split('-')[-1]
                    idx_date = datetime.strptime(date_str, '%Y.%m.%d')
                    if idx_date < cutoff_date:
                        size_bytes = parse_size(idx.get('pri.store.size', '0b'))
                        to_delete.append({
                            'index': idx['index'],
                            'size': idx.get('pri.store.size', '0 B'),
                            'date': date_str
                        })
                        total_size_bytes += size_bytes
                except:
                    continue

        def format_size(bytes):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes < 1024: return f"{bytes:.2f} {unit}"
                bytes /= 1024
            return f"{bytes:.2f} PB"

        return jsonify({
            'indices': to_delete,
            'total_count': len(to_delete),
            'total_size': format_size(total_size_bytes)
        })
    except Exception as e:
        logger.error(f"Error in cleanup preview: {str(e)}")
        return jsonify({'error': str(e)}), 500

@storage_bp.route('/api/storage/cleanup', methods=['POST'])
@login_required
def cleanup_indices():
    """Cleanup indices based on retention period"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        pattern = data.get('pattern', 'wazuh-archives-*')
        days = int(data.get('days', 30))
        
        opensearch = OpenSearchAPI()
        
        patterns = []
        if pattern == 'all':
            patterns = ['wazuh-archives-*', 'wazuh-alerts-*']
        else:
            patterns = [pattern]
            
        deleted_count = 0
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        for p in patterns:
            indices = opensearch.get_indices(p)
            for idx in indices:
                index_name = idx['index']
                try:
                    # Extract date from index name
                    date_str = index_name.split('-')[-1]
                    idx_date = datetime.strptime(date_str, '%Y.%m.%d')
                    
                    if idx_date < cutoff_date:
                        opensearch.delete_index(index_name)
                        deleted_count += 1
                        logger.info(f"Deleted old index: {index_name}")
                except (ValueError, IndexError):
                    continue
                
        return jsonify({
            'success': True,
            'message': f'Removed {deleted_count} logs older than {days} days'
        })
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        return jsonify({'error': str(e)}), 500
