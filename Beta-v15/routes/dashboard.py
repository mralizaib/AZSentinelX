from flask import Blueprint, render_template, jsonify, request, flash, current_app
from flask_login import login_required, current_user
import logging
from datetime import datetime, timedelta
from opensearch_api import OpenSearchAPI
from wazuh_api import WazuhAPI

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        opensearch = OpenSearchAPI()
        wazuh = WazuhAPI()
        
        days = int(request.args.get('days', 1))
        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        alert_counts = opensearch.get_alert_count_by_severity(start_time=start_time, end_time=end_time)
        recent_alerts = opensearch.search_alerts(start_time=start_time, end_time=end_time, limit=10, sort_field="@timestamp", sort_order="desc")
        agents_status = wazuh.get_agents({"limit": 500})
        
        # Include alert IDs in the response for correct navigation
        alerts_list = []
        if recent_alerts and 'results' in recent_alerts:
            for hit in recent_alerts['results']:
                alerts_list.append({
                    'id': hit.get('id'),
                    'index': hit.get('index'),
                    'source': hit.get('source')
                })
        
        agent_stats = {'total': 0, 'active': 0, 'disconnected': 0, 'never_connected': 0}
        if agents_status and 'data' in agents_status and isinstance(agents_status['data'], dict) and 'affected_items' in agents_status['data']:
            agents = agents_status['data']['affected_items']
            agent_stats['total'] = len(agents)
            for agent in agents:
                status = agent.get('status', '')
                if status == 'active': agent_stats['active'] += 1
                elif status == 'disconnected': agent_stats['disconnected'] += 1
                elif status == 'never_connected': agent_stats['never_connected'] += 1
        
        return jsonify({
            'alert_counts': alert_counts,
            'agent_stats': agent_stats,
            'recent_alerts': alerts_list,
            'time_range': {'start': start_time, 'end': end_time}
        })
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/dashboard/agents')
@login_required
def dashboard_agents():
    """Get agents list with optional status filter"""
    try:
        wazuh = WazuhAPI()
        status = request.args.get('status', 'all')
        filters = {"limit": 1000} # Increased limit to ensure we get all agents
        if status != 'all': filters["status"] = status
        agents_data = wazuh.get_agents(filters)
        agents_list = agents_data.get('data', {}).get('affected_items', []) if agents_data else []
        return jsonify(agents_list)
    except Exception as e:
        logger.error(f"Error fetching agents: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/dashboard/threat_analysis')
@login_required
def threat_analysis():
    try:
        opensearch = OpenSearchAPI()
        end_time = datetime.utcnow().isoformat()
        start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()
        
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
                    ]
                }
            },
            "aggs": {
                "locations": {
                    "terms": {
                        "field": "agent.labels.location.set",
                        "size": 100
                    }
                }
            }
        }
        
        response = opensearch.client.search(body=body, index=opensearch.index_pattern)
        locations = []
        if 'aggregations' in response and 'locations' in response['aggregations']:
            for bucket in response['aggregations']['locations']['buckets']:
                locations.append({
                    'name': bucket['key'],
                    'count': bucket['doc_count']
                })
        
        return jsonify({"locations": locations})
    except Exception as e:
        logger.error(f"Error getting threat analysis: {str(e)}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/dashboard/alerts_timeline')
@login_required
def alerts_timeline():
    try:
        opensearch = OpenSearchAPI()
        if not opensearch.client: return jsonify({'error': 'OpenSearch client not initialized'}), 500
        days = int(request.args.get('days', 1))
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        interval = '1h' if days <= 7 else '1d'
        body = {
            "size": 0,
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}]}},
            "aggs": {
                "alerts_over_time": {
                    "date_histogram": {"field": "@timestamp", "interval": interval},
                    "aggs": {
                        "severity": {
                            "range": {
                                "field": "rule.level",
                                "ranges": [
                                    {"to": 1, "key": "none"},
                                    {"from": 1, "to": 7, "key": "low"},
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
        timeline_data = []
        if 'aggregations' in response and 'alerts_over_time' in response['aggregations']:
            for bucket in response['aggregations']['alerts_over_time']['buckets']:
                data_point = {'timestamp': bucket['key_as_string'], 'total': bucket['doc_count']}
                for severity in bucket['severity']['buckets']:
                    data_point[severity['key']] = severity['doc_count']
                timeline_data.append(data_point)
        return jsonify(timeline_data)
    except Exception as e:
        logger.error(f"Error fetching alerts timeline: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/dashboard/top_rules')
@login_required
def top_rules():
    try:
        opensearch = OpenSearchAPI()
        if not opensearch.client: return jsonify({'error': 'OpenSearch client not initialized'}), 500
        days = int(request.args.get('days', 1))
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        body = {
            "size": 0,
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}]}},
            "aggs": {
                "rule_id": {
                    "terms": {"field": "rule.id", "size": 10},
                    "aggs": {
                        "rule_description": {"terms": {"field": "rule.description", "size": 1}},
                        "rule_level": {"terms": {"field": "rule.level", "size": 1}}
                    }
                }
            }
        }
        response = opensearch.client.search(body=body, index=opensearch.index_pattern)
        top_rules_data = []
        if 'aggregations' in response and 'rule_id' in response['aggregations']:
            for bucket in response['aggregations']['rule_id']['buckets']:
                top_rules_data.append({
                    'rule_id': bucket['key'],
                    'description': bucket['rule_description']['buckets'][0]['key'] if bucket['rule_description']['buckets'] else "N/A",
                    'level': bucket['rule_level']['buckets'][0]['key'] if bucket['rule_level']['buckets'] else 0,
                    'count': bucket['doc_count']
                })
        return jsonify(top_rules_data)
    except Exception as e:
        logger.error(f"Error fetching top rules: {str(e)}")
        return jsonify({'error': str(e)}), 500
