"""Wazuh server selection for the authenticated web session.

The actual client classes read the selected key from Flask's session, so every
existing Wazuh/OpenSearch-backed feature follows the same selection without
route-specific plumbing.
"""
from flask import Blueprint, jsonify, request, session
from flask_login import login_required

from config import Config

wazuh_bp = Blueprint('wazuh', __name__)


@wazuh_bp.route('/api/wazuh/servers')
@login_required
def list_servers():
    active = session.get('wazuh_server', 'primary')
    return jsonify({
        'servers': Config.get_server_options(),
        'active': active,
    })


@wazuh_bp.route('/api/wazuh/switch', methods=['POST'])
@login_required
def switch_server():
    data = request.get_json(silent=True) or {}
    server_key = data.get('server')
    profile = Config.get_server(server_key)

    if server_key not in ('primary', 'secondary'):
        return jsonify({'success': False, 'error': 'Unknown Wazuh server'}), 400

    configured = bool(
        profile['wazuh_url'] and profile['wazuh_user'] and profile['wazuh_password'] and
        profile['opensearch_url'] and profile['opensearch_user'] and profile['opensearch_password']
    )
    if not configured:
        return jsonify({
            'success': False,
            'error': f"{profile['name']} is not configured. Add its Wazuh and OpenSearch environment variables first.",
        }), 400

    # Store only the non-sensitive profile key in the signed session cookie.
    session['wazuh_server'] = server_key
    session.modified = True
    return jsonify({
        'success': True,
        'active': server_key,
        'name': profile['name'],
        'message': f"Connected to {profile['name']}.",
    })