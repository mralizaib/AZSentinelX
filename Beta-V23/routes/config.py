from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import logging
import json
from app import db
from models import SystemConfig

logger = logging.getLogger(__name__)

config_bp = Blueprint('config', __name__)

@config_bp.route('/api/config', methods=['GET'])
@login_required
def get_config():
    """Get all system configuration settings"""
    try:
        # Only admin users can access all config settings
        if not current_user.is_admin():
            return jsonify({'error': 'Unauthorized access'}), 403

        config_items = SystemConfig.query.all()

        result = []
        for item in config_items:
            result.append({
                'id': item.id,
                'key': item.key,
                'value': item.value,
                'description': item.description,
                'updated_at': item.updated_at.isoformat() if item.updated_at else None
            })

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting config: {str(e)}")
        return jsonify({'error': str(e)}), 500

@config_bp.route('/api/config/<key>', methods=['GET'])
@login_required
def get_config_value(key):
    """Get a specific configuration value by key"""
    try:
        # Some config values might be accessible to all users
        public_keys = ['alert_check_interval', 'dashboard_refresh_interval']

        if key not in public_keys and not current_user.is_admin():
            return jsonify({'error': 'Unauthorized access'}), 403

        value = SystemConfig.get_value(key)

        if value is None:
            return jsonify({'error': 'Configuration key not found'}), 404

        return jsonify({'key': key, 'value': value})
    except Exception as e:
        logger.error(f"Error getting config value: {str(e)}")
        return jsonify({'error': str(e)}), 500

@config_bp.route('/api/config', methods=['POST'])
@login_required
def update_config():
    """Update system configuration"""
    try:
        data = request.json

        for key, value in data.items():
            SystemConfig.set_value(key, str(value))

        db.session.commit()

        # Update scheduler if alert interval changed
        if 'alert_check_interval' in data:
            import scheduler
            scheduler.update_scheduler_jobs()

        return jsonify({
            'success': True,
            'message': 'Configuration updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating config: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@config_bp.route('/api/config/bulk', methods=['POST'])
@login_required
def set_bulk_config():
    """Set multiple configuration values at once"""
    try:
        # Only admin users can set configuration
        if not current_user.is_admin():
            return jsonify({'error': 'Unauthorized access'}), 403

        data = request.json

        if not data or not isinstance(data, list):
            return jsonify({'error': 'Expected a list of configuration items'}), 400

        updated = []

        for item in data:
            if 'key' not in item or 'value' not in item:
                continue

            key = item['key']
            value = item['value']
            description = item.get('description')

            config = SystemConfig.set_value(key, value, description)
            updated.append(config.key)

        return jsonify({
            'message': f'Updated {len(updated)} configuration values',
            'updated_keys': updated
        })
    except Exception as e:
        logger.error(f"Error setting bulk config: {str(e)}")
        return jsonify({'error': str(e)}), 500

@config_bp.route('/alert_check_interval', methods=['GET'])
@login_required
def get_alert_check_interval():
    """Get alert check interval"""
    try:
        return jsonify({'interval': current_app.config.get('ALERT_CHECK_INTERVAL', 300)})
    except Exception as e:
        logger.error(f"Error getting alert check interval: {str(e)}")
        return jsonify({'error': 'Failed to get alert check interval'}), 500

@config_bp.route('/dashboard_refresh_interval', methods=['GET'])
@login_required
def get_dashboard_refresh_interval():
    """Get dashboard refresh interval"""
    try:
        return jsonify({'interval': current_app.config.get('DASHBOARD_REFRESH_INTERVAL', 30)})
    except Exception as e:
        logger.error(f"Error getting dashboard refresh interval: {str(e)}")
        return jsonify({'error': 'Failed to get dashboard refresh interval'}), 500