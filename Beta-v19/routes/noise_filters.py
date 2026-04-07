"""
Noise Filter / Log Suppression Management Routes
Blueprint: noise_filters_bp  (url_prefix=/noise-filters)
"""

import json
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)
noise_filters_bp = Blueprint('noise_filters', __name__, url_prefix='/noise-filters')


# ── Pages ─────────────────────────────────────────────────────────────────────

@noise_filters_bp.route('/')
@login_required
def index():
    return render_template('noise_filters.html')


# ── Live Analysis API ─────────────────────────────────────────────────────────

@noise_filters_bp.route('/api/analysis')
@login_required
def analysis():
    try:
        hours = int(request.args.get('hours', 24))
        from log_filter_engine import live_noise_analysis
        data = live_noise_analysis(hours=hours)
        return jsonify(data)
    except Exception as exc:
        logger.error(f'Noise analysis error: {exc}')
        return jsonify({'error': str(exc)}), 500


# ── Filters CRUD API ──────────────────────────────────────────────────────────

@noise_filters_bp.route('/api/filters', methods=['GET'])
@login_required
def list_filters():
    from models import NoiseFilter
    try:
        filters = NoiseFilter.query.order_by(
            NoiseFilter.is_system.desc(), NoiseFilter.created_at.asc()
        ).all()
        return jsonify({'results': [_filter_dict(f) for f in filters]})
    except Exception as exc:
        logger.error(f'List filters error: {exc}')
        return jsonify({'error': str(exc)}), 500


@noise_filters_bp.route('/api/filters', methods=['POST'])
@login_required
def create_filter():
    from models import db, NoiseFilter
    try:
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'Filter name is required'}), 400

        filter_type = data.get('filter_type', 'rule_id')
        if filter_type not in ('rule_id', 'rule_group', 'min_level', 'description_contains', 'agent'):
            return jsonify({'error': 'Invalid filter type'}), 400

        f = NoiseFilter(
            name=name,
            filter_type=filter_type,
            filter_value=(data.get('filter_value') or '').strip(),
            action=data.get('action', 'suppress'),
            notes=data.get('notes', ''),
            enabled=bool(data.get('enabled', True)),
            estimated_daily=int(data.get('estimated_daily', 0)),
            is_system=False,
            created_by=current_user.id,
        )
        db.session.add(f)
        db.session.commit()
        return jsonify({'success': True, 'filter': _filter_dict(f)})
    except Exception as exc:
        logger.error(f'Create filter error: {exc}')
        return jsonify({'error': str(exc)}), 500


@noise_filters_bp.route('/api/filters/<int:filter_id>', methods=['PUT'])
@login_required
def update_filter(filter_id):
    from models import db, NoiseFilter
    try:
        f    = NoiseFilter.query.get_or_404(filter_id)
        data = request.get_json() or {}

        if 'enabled'          in data: f.enabled          = bool(data['enabled'])
        if 'name'             in data: f.name             = data['name']
        if 'notes'            in data: f.notes            = data['notes']
        if 'filter_value'     in data: f.filter_value     = data['filter_value']
        if 'action'           in data: f.action           = data['action']
        if 'estimated_daily'  in data: f.estimated_daily  = int(data['estimated_daily'])

        db.session.commit()
        return jsonify({'success': True, 'filter': _filter_dict(f)})
    except Exception as exc:
        logger.error(f'Update filter error: {exc}')
        return jsonify({'error': str(exc)}), 500


@noise_filters_bp.route('/api/filters/<int:filter_id>', methods=['DELETE'])
@login_required
def delete_filter(filter_id):
    from models import db, NoiseFilter
    try:
        f = NoiseFilter.query.get_or_404(filter_id)
        if f.is_system:
            return jsonify({'error': 'System filters cannot be deleted. Disable them instead.'}), 400
        db.session.delete(f)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as exc:
        logger.error(f'Delete filter error: {exc}')
        return jsonify({'error': str(exc)}), 500


@noise_filters_bp.route('/api/filters/seed', methods=['POST'])
@login_required
def seed_filters():
    from flask import current_app
    from log_filter_engine import seed_default_filters
    try:
        seed_default_filters(current_app._get_current_object())
        return jsonify({'success': True, 'message': 'Default filters seeded'})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ── Internal helper ───────────────────────────────────────────────────────────

def _filter_dict(f) -> dict:
    return {
        'id':             f.id,
        'name':           f.name,
        'filter_type':    f.filter_type,
        'filter_value':   f.filter_value,
        'action':         f.action,
        'enabled':        f.enabled,
        'is_system':      f.is_system,
        'estimated_daily':f.estimated_daily or 0,
        'notes':          f.notes or '',
        'created_at':     f.created_at.isoformat() if f.created_at else '',
    }
