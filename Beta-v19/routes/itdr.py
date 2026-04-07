"""
ITDR / XDR Blueprint
Routes for the Identity Threat Detection & Response / Extended Detection & Response module.
"""

import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)
itdr_bp = Blueprint('itdr', __name__)


# ── Helper ────────────────────────────────────────────────────────────────────

def _sev_rank(s):
    return {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}.get(s, 0)


# ── Pages ─────────────────────────────────────────────────────────────────────

@itdr_bp.route('/itdr')
@login_required
def index():
    from itdr_engine import get_detection_rule_meta
    rules = get_detection_rule_meta()
    return render_template('itdr.html', detection_rules=rules)


# ── Stats API ─────────────────────────────────────────────────────────────────

@itdr_bp.route('/api/itdr/stats')
@login_required
def stats():
    from models import ITDRDetection, XDRIncident, RemediationPolicy, RemediationAction
    try:
        since_24h = datetime.utcnow() - timedelta(hours=24)
        since_7d  = datetime.utcnow() - timedelta(days=7)

        open_incidents    = XDRIncident.query.filter(XDRIncident.status.in_(['open', 'investigating'])).count()
        critical_detects  = ITDRDetection.query.filter(ITDRDetection.severity == 'critical', ITDRDetection.detected_at >= since_24h).count()
        total_detects_24h = ITDRDetection.query.filter(ITDRDetection.detected_at >= since_24h).count()
        active_policies   = RemediationPolicy.query.filter_by(enabled=True).count()
        actions_taken_7d  = RemediationAction.query.filter(RemediationAction.executed_at >= since_7d, RemediationAction.status == 'success').count()
        resolved_7d       = XDRIncident.query.filter(XDRIncident.status == 'resolved', XDRIncident.resolved_at >= since_7d).count()

        # Category breakdown (last 7 days)
        all_dets = ITDRDetection.query.filter(ITDRDetection.detected_at >= since_7d).all()
        cat_counts = {}
        for d in all_dets:
            cat_counts[d.category] = cat_counts.get(d.category, 0) + 1

        return jsonify({
            'open_incidents':    open_incidents,
            'critical_detects':  critical_detects,
            'total_detects_24h': total_detects_24h,
            'active_policies':   active_policies,
            'actions_taken_7d':  actions_taken_7d,
            'resolved_7d':       resolved_7d,
            'category_breakdown': cat_counts,
        })
    except Exception as exc:
        logger.error(f'ITDR stats error: {exc}')
        return jsonify({'error': str(exc)}), 500


# ── Detections API ────────────────────────────────────────────────────────────

@itdr_bp.route('/api/itdr/detections')
@login_required
def detections():
    from models import ITDRDetection
    try:
        page     = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        severity = request.args.get('severity', '')
        category = request.args.get('category', '')
        since_h  = int(request.args.get('hours', 48))

        since_dt = datetime.utcnow() - timedelta(hours=since_h)
        q = ITDRDetection.query.filter(ITDRDetection.detected_at >= since_dt)

        if severity:
            q = q.filter(ITDRDetection.severity == severity)
        if category:
            q = q.filter(ITDRDetection.category == category)

        q = q.order_by(ITDRDetection.detected_at.desc())
        total = q.count()
        items = q.offset((page - 1) * per_page).limit(per_page).all()

        results = []
        for d in items:
            results.append({
                'id':            d.id,
                'detection_id':  d.detection_id,
                'rule_id':       d.rule_id,
                'rule_name':     d.rule_name,
                'category':      d.category,
                'severity':      d.severity,
                'source_ip':     d.source_ip or '',
                'target_agents': d.get_target_agents(),
                'event_count':   d.event_count,
                'first_seen':    d.first_seen.isoformat() if d.first_seen else '',
                'last_seen':     d.last_seen.isoformat()  if d.last_seen  else '',
                'detected_at':   d.detected_at.isoformat() if d.detected_at else '',
                'details':       d.get_details(),
                'incident_id':   d.incident_id,
                'alert_sent':    d.alert_sent,
                'remediated':    d.remediated,
            })

        return jsonify({'total': total, 'page': page, 'results': results})
    except Exception as exc:
        logger.error(f'ITDR detections error: {exc}')
        return jsonify({'error': str(exc)}), 500


# ── Incidents API ─────────────────────────────────────────────────────────────

@itdr_bp.route('/api/itdr/incidents')
@login_required
def incidents():
    from models import XDRIncident
    try:
        status   = request.args.get('status', '')
        severity = request.args.get('severity', '')
        page     = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))

        q = XDRIncident.query
        if status:
            q = q.filter(XDRIncident.status == status)
        if severity:
            q = q.filter(XDRIncident.severity == severity)

        q = q.order_by(XDRIncident.updated_at.desc())
        total = q.count()
        items = q.offset((page - 1) * per_page).limit(per_page).all()

        results = []
        for inc in items:
            results.append({
                'id':              inc.id,
                'incident_number': inc.incident_number,
                'title':           inc.title,
                'status':          inc.status,
                'severity':        inc.severity,
                'categories':      inc.get_categories(),
                'affected_agents': inc.get_affected_agents(),
                'source_ips':      inc.get_source_ips(),
                'detection_count': inc.detection_count,
                'created_at':      inc.created_at.isoformat() if inc.created_at else '',
                'updated_at':      inc.updated_at.isoformat() if inc.updated_at else '',
                'resolved_at':     inc.resolved_at.isoformat() if inc.resolved_at else '',
                'recommended_actions': inc.get_recommended_actions(),
                'ai_summary':      inc.ai_summary or '',
            })

        return jsonify({'total': total, 'page': page, 'results': results})
    except Exception as exc:
        logger.error(f'ITDR incidents error: {exc}')
        return jsonify({'error': str(exc)}), 500


@itdr_bp.route('/api/itdr/incidents/<int:incident_id>/status', methods=['POST'])
@login_required
def update_incident_status(incident_id):
    from models import db, XDRIncident
    try:
        data   = request.get_json() or {}
        status = data.get('status', '')
        if status not in ('open', 'investigating', 'contained', 'resolved'):
            return jsonify({'error': 'Invalid status'}), 400

        inc = XDRIncident.query.get_or_404(incident_id)
        inc.status     = status
        inc.updated_at = datetime.utcnow()
        if status == 'resolved' and not inc.resolved_at:
            inc.resolved_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'status': status})
    except Exception as exc:
        logger.error(f'Update incident status error: {exc}')
        return jsonify({'error': str(exc)}), 500


@itdr_bp.route('/api/itdr/incidents/<int:incident_id>/detections')
@login_required
def incident_detections(incident_id):
    from models import ITDRDetection
    try:
        dets = ITDRDetection.query.filter_by(incident_id=incident_id).order_by(ITDRDetection.detected_at.asc()).all()
        results = [{
            'id':          d.id,
            'rule_id':     d.rule_id,
            'rule_name':   d.rule_name,
            'category':    d.category,
            'severity':    d.severity,
            'source_ip':   d.source_ip or '',
            'target_agents': d.get_target_agents(),
            'event_count': d.event_count,
            'detected_at': d.detected_at.isoformat() if d.detected_at else '',
            'details':     d.get_details(),
        } for d in dets]
        return jsonify({'results': results})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ── Scan API ──────────────────────────────────────────────────────────────────

@itdr_bp.route('/api/itdr/scan', methods=['POST'])
@login_required
def trigger_scan():
    """Trigger an immediate ITDR scan in a background thread."""
    import threading
    from flask import current_app

    app = current_app._get_current_object()

    def _run():
        try:
            from itdr_engine import run_itdr_scan
            run_itdr_scan(app)
        except Exception as exc:
            logger.error(f'Manual ITDR scan error: {exc}', exc_info=True)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({'success': True, 'message': 'ITDR scan started in background'})


# ── Policies API ──────────────────────────────────────────────────────────────

@itdr_bp.route('/api/itdr/policies', methods=['GET'])
@login_required
def list_policies():
    from models import RemediationPolicy
    try:
        policies = RemediationPolicy.query.order_by(RemediationPolicy.created_at.desc()).all()
        return jsonify({'results': [_policy_dict(p) for p in policies]})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@itdr_bp.route('/api/itdr/policies', methods=['POST'])
@login_required
def create_policy():
    from models import db, RemediationPolicy
    try:
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'Policy name is required'}), 400

        action_type = data.get('action_type', 'email')
        if action_type not in ('email', 'webhook', 'escalate'):
            return jsonify({'error': 'Invalid action type'}), 400

        cats = data.get('trigger_categories', [])
        sevs = data.get('trigger_severities', [])

        p = RemediationPolicy(
            name=name,
            description=data.get('description', ''),
            enabled=bool(data.get('enabled', True)),
            trigger_categories=json.dumps(cats),
            trigger_severities=json.dumps(sevs),
            trigger_min_event_count=int(data.get('trigger_min_event_count', 1)),
            action_type=action_type,
            action_email=data.get('action_email', ''),
            action_webhook_url=data.get('action_webhook_url', ''),
            action_webhook_secret=data.get('action_webhook_secret', ''),
            created_by=current_user.id,
        )
        db.session.add(p)
        db.session.commit()
        return jsonify({'success': True, 'policy': _policy_dict(p)})
    except Exception as exc:
        logger.error(f'Create policy error: {exc}')
        return jsonify({'error': str(exc)}), 500


@itdr_bp.route('/api/itdr/policies/<int:policy_id>', methods=['PUT'])
@login_required
def update_policy(policy_id):
    from models import db, RemediationPolicy
    try:
        p    = RemediationPolicy.query.get_or_404(policy_id)
        data = request.get_json() or {}

        if 'name'        in data: p.name        = data['name']
        if 'description' in data: p.description = data['description']
        if 'enabled'     in data: p.enabled      = bool(data['enabled'])
        if 'trigger_categories'       in data: p.trigger_categories       = json.dumps(data['trigger_categories'])
        if 'trigger_severities'       in data: p.trigger_severities       = json.dumps(data['trigger_severities'])
        if 'trigger_min_event_count'  in data: p.trigger_min_event_count  = int(data['trigger_min_event_count'])
        if 'action_type'              in data: p.action_type              = data['action_type']
        if 'action_email'             in data: p.action_email             = data['action_email']
        if 'action_webhook_url'       in data: p.action_webhook_url       = data['action_webhook_url']
        if 'action_webhook_secret'    in data: p.action_webhook_secret    = data['action_webhook_secret']

        db.session.commit()
        return jsonify({'success': True, 'policy': _policy_dict(p)})
    except Exception as exc:
        logger.error(f'Update policy error: {exc}')
        return jsonify({'error': str(exc)}), 500


@itdr_bp.route('/api/itdr/policies/<int:policy_id>', methods=['DELETE'])
@login_required
def delete_policy(policy_id):
    from models import db, RemediationPolicy
    try:
        p = RemediationPolicy.query.get_or_404(policy_id)
        db.session.delete(p)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as exc:
        logger.error(f'Delete policy error: {exc}')
        return jsonify({'error': str(exc)}), 500


# ── Remediation Log API ───────────────────────────────────────────────────────

@itdr_bp.route('/api/itdr/remediation-log')
@login_required
def remediation_log():
    from models import RemediationAction, RemediationPolicy
    try:
        page     = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 30))
        since_7d = datetime.utcnow() - timedelta(days=7)

        q = RemediationAction.query.filter(RemediationAction.executed_at >= since_7d)
        q = q.order_by(RemediationAction.executed_at.desc())
        total = q.count()
        items = q.offset((page - 1) * per_page).limit(per_page).all()

        results = []
        for a in items:
            policy_name = a.policy.name if a.policy else '—'
            results.append({
                'id':             a.id,
                'policy_name':    policy_name,
                'action_type':    a.action_type,
                'status':         a.status,
                'result_message': a.result_message or '',
                'executed_at':    a.executed_at.isoformat() if a.executed_at else '',
                'detection_id':   a.detection_id,
                'incident_id':    a.incident_id,
            })
        return jsonify({'total': total, 'results': results})
    except Exception as exc:
        logger.error(f'Remediation log error: {exc}')
        return jsonify({'error': str(exc)}), 500


# ── Internal helper ───────────────────────────────────────────────────────────

def _policy_dict(p) -> dict:
    return {
        'id':                     p.id,
        'name':                   p.name,
        'description':            p.description or '',
        'enabled':                p.enabled,
        'trigger_categories':     p.get_trigger_categories(),
        'trigger_severities':     p.get_trigger_severities(),
        'trigger_min_event_count':p.trigger_min_event_count or 1,
        'action_type':            p.action_type or '',
        'action_email':           p.action_email or '',
        'action_webhook_url':     p.action_webhook_url or '',
        'created_at':             p.created_at.isoformat() if p.created_at else '',
    }
