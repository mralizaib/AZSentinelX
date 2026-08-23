"""Shared Wazuh Center/Site selection for all existing dashboards and APIs."""
from flask import Blueprint, jsonify, redirect, request, session, url_for
from flask_login import login_required
from config import Config

centers_bp = Blueprint('centers', __name__)


@centers_bp.get('/api/centers')
@login_required
def list_centers():
    centers = Config.wazuh_centers()
    return jsonify({
        'centers': [{'id': key, 'name': value['name']} for key, value in centers.items()],
        'selected': session.get('wazuh_center', 'current'),
    })


@centers_bp.post('/api/centers/select')
@login_required
def select_center():
    center_id = (request.get_json() or {}).get('center_id', 'current')
    if center_id not in Config.wazuh_centers():
        return jsonify({'success': False, 'error': 'Center is not configured'}), 400
    session['wazuh_center'] = center_id
    session.modified = True
    return jsonify({'success': True, 'selected': center_id})