"""
Auditor Dashboard — a clean, compliance-focused view for auditor role users.

Shows only actionable security incidents (critical, high, medium) excluding
suppressed noisy rule IDs. Designed for compliance audits where dashboard
statistics must represent real security risks, not operational noise.
"""
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
import logging
from datetime import datetime, timedelta
from opensearch_api import OpenSearchAPI

logger = logging.getLogger(__name__)

auditor_dashboard_bp = Blueprint('auditor_dashboard', __name__)
from routes.permissions import make_blueprint_permission_check
auditor_dashboard_bp.before_request(make_blueprint_permission_check('auditor_dashboard'))

# Suppressed rule IDs — same list as in dashboard.py
SUPPRESSED_RULE_IDS = [750, 60642, 752, 550, 60106, 4804, 60104, 61102, 4803, 60608]


@auditor_dashboard_bp.route('/auditor')
@login_required
def index():
    return render_template('auditor_dashboard.html')


@auditor_dashboard_bp.route('/api/auditor/stats')
@login_required
def auditor_stats():
    """
    Security incident counts for auditors — excludes suppressed noisy rules.
    Only returns critical, high, and medium alerts (actionable threats).
    """
    try:
        opensearch = OpenSearchAPI()
        days = int(request.args.get('days', 7))
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}}
                    ],
                    "must_not": [
                        {"terms": {"rule.id": SUPPRESSED_RULE_IDS}}
                    ]
                }
            },
            "aggs": {
                # Severity buckets — only actionable levels
                "severity_counts": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"from": 15, "key": "critical"},   # Level 15+
                            {"from": 12, "to": 15, "key": "high"},  # Levels 12-14
                            {"from": 7, "to": 12, "key": "medium"},  # Levels 7-11
                        ]
                    }
                },
                # Top threat categories by rule group
                "threat_categories": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                # Top rules (most frequent security incidents)
                "top_rules": {
                    "terms": {"field": "rule.id", "size": 8},
                    "aggs": {
                        "rule_description": {"terms": {"field": "rule.description", "size": 1}},
                        "rule_level": {"terms": {"field": "rule.level", "size": 1}}
                    }
                },
                # Top agents with incidents
                "top_agents": {
                    "terms": {"field": "agent.name", "size": 8},
                    "aggs": {
                        "agent_ip": {"terms": {"field": "agent.ip", "size": 1}}
                    }
                },
                # Only high+critical for priority alerts
                "high_critical_total": {
                    "filter": {"range": {"rule.level": {"gte": 12}}}
                }
            }
        }

        response = opensearch.client.search(body=body, index=opensearch.index_pattern)
        aggs = response.get('aggregations', {})

        # Build severity counts
        severity = {}
        for bucket in aggs.get('severity_counts', {}).get('buckets', []):
            severity[bucket['key']] = bucket['doc_count']

        # Build top rules
        top_rules = []
        for bucket in aggs.get('top_rules', {}).get('buckets', []):
            desc_buckets = bucket.get('rule_description', {}).get('buckets', [])
            level_buckets = bucket.get('rule_level', {}).get('buckets', [])
            top_rules.append({
                'rule_id': bucket['key'],
                'description': desc_buckets[0]['key'] if desc_buckets else 'N/A',
                'level': level_buckets[0]['key'] if level_buckets else 0,
                'count': bucket['doc_count']
            })

        # Build top agents
        top_agents = []
        for bucket in aggs.get('top_agents', {}).get('buckets', []):
            ip_buckets = bucket.get('agent_ip', {}).get('buckets', [])
            top_agents.append({
                'name': bucket['key'],
                'ip': ip_buckets[0]['key'] if ip_buckets else 'N/A',
                'count': bucket['doc_count']
            })

        # Threat categories
        categories = [
            {'name': b['key'], 'count': b['doc_count']}
            for b in aggs.get('threat_categories', {}).get('buckets', [])
        ]

        total_actionable = sum(severity.values())
        high_critical = aggs.get('high_critical_total', {}).get('doc_count', 0)

        return jsonify({
            'severity': severity,
            'total_actionable': total_actionable,
            'high_critical': high_critical,
            'top_rules': top_rules,
            'top_agents': top_agents,
            'categories': categories,
            'time_range': {'days': days, 'start': start_time.isoformat(), 'end': end_time.isoformat()}
        })

    except Exception as e:
        logger.error(f"Error fetching auditor stats: {str(e)}")
        return jsonify({'error': str(e)}), 500


@auditor_dashboard_bp.route('/api/auditor/timeline')
@login_required
def auditor_timeline():
    """Alert trend for auditor — only actionable severity, no suppressed rules."""
    try:
        opensearch = OpenSearchAPI()
        days = int(request.args.get('days', 7))
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        interval = '1h' if days <= 2 else '1d'

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                        {"range": {"rule.level": {"gte": 7}}}  # Medium and above only
                    ],
                    "must_not": [{"terms": {"rule.id": SUPPRESSED_RULE_IDS}}]
                }
            },
            "aggs": {
                "over_time": {
                    "date_histogram": {"field": "@timestamp", "interval": interval},
                    "aggs": {
                        "severity": {
                            "range": {
                                "field": "rule.level",
                                "ranges": [
                                    {"from": 7, "to": 12, "key": "medium"},
                                    {"from": 12, "to": 15, "key": "high"},
                                    {"from": 15, "key": "critical"}
                                ]
                            }
                        }
                    }
                }
            }
        }

        response = opensearch.client.search(body=body, index=opensearch.index_pattern)
        timeline = []
        for bucket in response.get('aggregations', {}).get('over_time', {}).get('buckets', []):
            point = {'timestamp': bucket['key_as_string'], 'total': bucket['doc_count']}
            for sev in bucket.get('severity', {}).get('buckets', []):
                point[sev['key']] = sev['doc_count']
            timeline.append(point)

        return jsonify(timeline)
    except Exception as e:
        logger.error(f"Error fetching auditor timeline: {str(e)}")
        return jsonify({'error': str(e)}), 500
