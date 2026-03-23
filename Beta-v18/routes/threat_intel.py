from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

threat_intel_bp = Blueprint('threat_intel', __name__)


@threat_intel_bp.route('/threat-intel')
@login_required
def index():
    from models import ThreatIntelItem, ThreatIntelConfig, db
    from threat_intel_service import FEED_SOURCES
    cfg = ThreatIntelConfig.get_instance()
    return render_template('threat_intel.html', cfg=cfg, feed_sources=FEED_SOURCES)


@threat_intel_bp.route('/api/threat-intel/items')
@login_required
def list_items():
    from models import ThreatIntelItem, db
    from threat_intel_service import FEED_SOURCES

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    severity = request.args.get('severity', '')
    source = request.args.get('source', '')
    has_patch = request.args.get('has_patch', '')
    search = request.args.get('search', '').strip()
    exposed = request.args.get('exposed', '')

    query = ThreatIntelItem.query.order_by(ThreatIntelItem.published_at.desc())

    if severity:
        query = query.filter(ThreatIntelItem.severity == severity)
    if source:
        query = query.filter(ThreatIntelItem.source == source)
    if has_patch == 'true':
        query = query.filter(ThreatIntelItem.has_patch == True)
    if search:
        query = query.filter(ThreatIntelItem.title.ilike(f'%{search}%'))
    if exposed == 'true':
        from models import ThreatIntelCorrelation
        exposed_ids = db.session.query(ThreatIntelCorrelation.threat_intel_item_id).filter(
            ThreatIntelCorrelation.affected_count > 0
        ).subquery()
        query = query.filter(ThreatIntelItem.id.in_(exposed_ids))

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    results = []
    for item in items:
        analysis = {}
        if item.ai_analysis:
            try:
                analysis = json.loads(item.ai_analysis)
            except Exception:
                pass

        corr = item.correlation
        results.append({
            'id': item.id,
            'title': item.title,
            'description': item.description[:300] if item.description else '',
            'url': item.url,
            'source': item.source,
            'source_name': FEED_SOURCES.get(item.source, {}).get('name', item.source),
            'source_color': FEED_SOURCES.get(item.source, {}).get('color', 'secondary'),
            'published_at': item.published_at.strftime('%Y-%m-%d %H:%M') if item.published_at else '',
            'fetched_at': item.fetched_at.strftime('%Y-%m-%d %H:%M') if item.fetched_at else '',
            'severity': item.severity,
            'has_patch': item.has_patch,
            'has_mitigation': item.has_mitigation,
            'relevance_score': item.relevance_score,
            'ai_analyzed': item.ai_analyzed,
            'email_sent': item.email_sent,
            'cve_ids': item.get_cve_list(),
            'summary': analysis.get('summary', ''),
            'recommended_action': analysis.get('recommended_action', ''),
            'affected_count': corr.affected_count if corr else 0,
            'is_confirmed': corr.is_confirmed_present if corr else False,
        })

    return jsonify({
        'items': results,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
    })


@threat_intel_bp.route('/api/threat-intel/stats')
@login_required
def stats():
    from models import ThreatIntelItem, db
    from sqlalchemy import func

    from models import ThreatIntelCorrelation
    total = ThreatIntelItem.query.count()
    by_severity = db.session.query(
        ThreatIntelItem.severity, func.count(ThreatIntelItem.id)
    ).group_by(ThreatIntelItem.severity).all()
    by_source = db.session.query(
        ThreatIntelItem.source, func.count(ThreatIntelItem.id)
    ).group_by(ThreatIntelItem.source).all()
    with_patch = ThreatIntelItem.query.filter_by(has_patch=True).count()
    emails_sent = ThreatIntelItem.query.filter_by(email_sent=True).count()
    analysed = ThreatIntelItem.query.filter_by(ai_analyzed=True).count()

    infra_exposed = db.session.query(func.count(ThreatIntelCorrelation.id)).filter(
        ThreatIntelCorrelation.affected_count > 0
    ).scalar() or 0
    confirmed_in_env = db.session.query(func.count(ThreatIntelCorrelation.id)).filter(
        ThreatIntelCorrelation.is_confirmed_present == True
    ).scalar() or 0

    return jsonify({
        'total': total,
        'by_severity': dict(by_severity),
        'by_source': dict(by_source),
        'with_patch': with_patch,
        'emails_sent': emails_sent,
        'analysed': analysed,
        'infra_exposed': infra_exposed,
        'confirmed_in_env': confirmed_in_env,
    })


@threat_intel_bp.route('/api/threat-intel/refresh', methods=['POST'])
@login_required
def manual_refresh():
    from flask import current_app
    try:
        from threat_intel_service import run_full_refresh
        import threading
        app = current_app._get_current_object()

        def run():
            run_full_refresh(app)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return jsonify({'success': True, 'message': 'Refresh started in background. Check back shortly.'})
    except Exception as e:
        logger.error(f"Error triggering refresh: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/configure', methods=['POST'])
@login_required
def configure():
    from models import ThreatIntelConfig, db
    from threat_intel_service import FEED_SOURCES
    try:
        data = request.json or {}
        cfg = ThreatIntelConfig.get_instance()
        cfg.email_recipient = data.get('email_recipient', cfg.email_recipient)
        cfg.enabled = bool(data.get('enabled', cfg.enabled))
        cfg.notify_on_patch = bool(data.get('notify_on_patch', cfg.notify_on_patch))
        cfg.notify_on_critical = bool(data.get('notify_on_critical', cfg.notify_on_critical))
        min_rel = data.get('min_relevance', cfg.min_relevance)
        try:
            cfg.min_relevance = max(1, min(10, int(min_rel)))
        except (ValueError, TypeError):
            pass
        raw_sources = data.get('sources', cfg.get_sources())
        valid_sources = [s for s in raw_sources if s in FEED_SOURCES]
        cfg.set_sources(valid_sources if valid_sources else list(FEED_SOURCES.keys()))
        cfg.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error saving threat intel config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/item/<int:item_id>')
@login_required
def get_item(item_id):
    from models import ThreatIntelItem
    from threat_intel_service import FEED_SOURCES
    item = ThreatIntelItem.query.get_or_404(item_id)
    analysis = {}
    if item.ai_analysis:
        try:
            analysis = json.loads(item.ai_analysis)
        except Exception:
            pass

    correlation_data = None
    corr = item.correlation
    if corr:
        correlation_data = {
            'correlated_at': corr.correlated_at.strftime('%Y-%m-%d %H:%M') if corr.correlated_at else '',
            'affected_count': corr.affected_count,
            'env_relevance_score': corr.env_relevance_score,
            'env_recommended_action': corr.env_recommended_action or '',
            'correlation_summary': corr.correlation_summary or '',
            'is_confirmed_present': corr.is_confirmed_present,
            'affected_agents': corr.get_affected_agents(),
        }

    return jsonify({
        'id': item.id,
        'title': item.title,
        'description': item.description or '',
        'url': item.url,
        'source': item.source,
        'source_name': FEED_SOURCES.get(item.source, {}).get('name', item.source),
        'source_color': FEED_SOURCES.get(item.source, {}).get('color', 'secondary'),
        'published_at': item.published_at.strftime('%Y-%m-%d %H:%M') if item.published_at else '',
        'fetched_at': item.fetched_at.strftime('%Y-%m-%d %H:%M') if item.fetched_at else '',
        'severity': item.severity,
        'has_patch': item.has_patch,
        'has_mitigation': item.has_mitigation,
        'relevance_score': item.relevance_score,
        'ai_analyzed': item.ai_analyzed,
        'email_sent': item.email_sent,
        'cve_ids': item.get_cve_list(),
        'summary': analysis.get('summary', ''),
        'recommended_action': analysis.get('recommended_action', ''),
        'correlation': correlation_data,
    })


@threat_intel_bp.route('/api/threat-intel/item/<int:item_id>/analyse', methods=['POST'])
@login_required
def analyse_single(item_id):
    from models import ThreatIntelItem, db
    from threat_intel_service import analyse_item_with_ai
    try:
        item = ThreatIntelItem.query.get_or_404(item_id)
        result = analyse_item_with_ai(item)
        item.ai_analysis = json.dumps(result)
        item.ai_analyzed = True
        item.severity = result.get('severity', item.severity)
        item.relevance_score = result.get('relevance_score', 5)
        item.has_patch = result.get('has_patch', item.has_patch)
        item.has_mitigation = result.get('has_mitigation', item.has_mitigation)
        db.session.commit()
        return jsonify({'success': True, 'analysis': result})
    except Exception as e:
        logger.error(f"Error analysing item {item_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/item/<int:item_id>/correlate', methods=['POST'])
@login_required
def correlate_single(item_id):
    """Correlate a single threat intel item against the internal infrastructure on demand."""
    from flask import current_app
    try:
        from threat_intel_correlator import correlate_single_item
        app = current_app._get_current_object()
        result = correlate_single_item(app, item_id)
        if 'error' in result:
            err = result['error']
            code = 404 if 'not found' in err.lower() else 503
            return jsonify({'success': False, 'error': err}), code
        return jsonify({'success': True, 'correlation': result})
    except Exception as e:
        logger.error(f"Error correlating item {item_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/correlate-all', methods=['POST'])
@login_required
def correlate_all():
    """Run infrastructure correlation on all unprocessed items in background."""
    from flask import current_app
    import threading
    try:
        from threat_intel_correlator import correlate_items
        app = current_app._get_current_object()

        def run():
            correlate_items(app, max_items=50)

        threading.Thread(target=run, daemon=True).start()
        return jsonify({'success': True, 'message': 'Correlation started in background. Refresh items shortly.'})
    except Exception as e:
        logger.error(f"Error starting correlate-all: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
