from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import db, ExternalIntegration
import requests
import json
import logging

logger = logging.getLogger(__name__)
integrations_bp = Blueprint('integrations', __name__, url_prefix='/integrations')

@integrations_bp.route('/')
@login_required
def index():
    integrations = ExternalIntegration.query.filter_by(user_id=current_user.id).all()
    return render_template('integrations/index.html', integrations=integrations)

@integrations_bp.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form.get('name')
    url = request.form.get('url')
    integration_type = request.form.get('type', 'webhook')
    api_key = request.form.get('api_key')
    severity = request.form.get('severity', 12)

    if not name or not url:
        flash('Name and URL are required', 'danger')
        return redirect(url_for('integrations.index'))

    new_integration = ExternalIntegration(
        user_id=current_user.id,
        name=name,
        url=url,
        integration_type=integration_type,
        api_key=api_key,
        severity_threshold=int(severity)
    )
    db.session.add(new_integration)
    db.session.commit()
    flash('Integration added successfully', 'success')
    return redirect(url_for('integrations.index'))

@integrations_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    integration = ExternalIntegration.query.get_or_404(id)
    if integration.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(integration)
    db.session.commit()
    flash('Integration deleted', 'info')
    return redirect(url_for('integrations.index'))

def send_alert_to_integrations(alert_data):
    """Utility function to send alerts to all enabled external integrations"""
    try:
        from models import ExternalIntegration
        severity_level = alert_data.get('rule', {}).get('level', 0)
        
        # Ensure we have a database session
        enabled_integrations = ExternalIntegration.query.filter_by(enabled=True).all()
        
        for integration in enabled_integrations:
            if severity_level >= integration.severity_threshold:
                try:
                    headers = {'Content-Type': 'application/json'}
                    if integration.api_key:
                        headers['X-API-Key'] = integration.api_key
                    
                    response = requests.post(
                        integration.url, 
                        json=alert_data, 
                        headers=headers,
                        timeout=5
                    )
                    logger.info(f"Sent alert to {integration.name}: status {response.status_code}")
                except Exception as e:
                    logger.error(f"Failed to send alert to {integration.name}: {e}")
    except Exception as e:
        logger.error(f"Error in send_alert_to_integrations: {e}")
