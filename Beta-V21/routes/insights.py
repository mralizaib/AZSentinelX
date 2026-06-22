from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import logging
from datetime import datetime, timedelta
import json
import re
from app import db
from models import AiInsightTemplate, AiInsightResult, Conversation
from ai_insights import AIInsights
from opensearch_api import OpenSearchAPI

logger = logging.getLogger(__name__)

insights_bp = Blueprint('insights', __name__)

@insights_bp.route('/insights')
@login_required
def index():
    # Check if there's an action parameter indicating we should analyze
    action = request.args.get('action')
    
    # Get user's insight templates
    templates = AiInsightTemplate.query.filter_by(user_id=current_user.id).all()
    
    # If action is analyze, we should show the analyze form directly
    show_analyze_form = (action == 'analyze')
    
    return render_template('insights.html', 
                          templates=templates, 
                          show_analyze_form=show_analyze_form,
                          active_tab='analyze' if show_analyze_form else 'templates')

@insights_bp.route('/api/insights/templates', methods=['GET'])
@login_required
def get_templates():
    """Get all AI insight templates for the current user"""
    try:
        templates = AiInsightTemplate.query.filter_by(user_id=current_user.id).all()
        
        templates_list = []
        for template in templates:
            templates_list.append({
                'id': template.id,
                'name': template.name,
                'description': template.description,
                'fields': template.get_fields(),
                'model_type': template.model_type,
                'created_at': template.created_at.isoformat()
            })
        
        return jsonify(templates_list)
    except Exception as e:
        logger.error(f"Error getting insight templates: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/templates', methods=['POST'])
@login_required
def create_template():
    """Create a new AI insight template"""
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Template name is required'}), 400
        
        if not data.get('fields'):
            return jsonify({'error': 'At least one field must be selected'}), 400
        
        # Create new template
        new_template = AiInsightTemplate()
        new_template.user_id = current_user.id
        new_template.name = data.get('name')
        new_template.description = data.get('description', 'rule.description')
        new_template.model_type = data.get('model_type', 'openai')
        
        # Set JSON fields
        new_template.set_fields(data.get('fields'))
        
        # Save to database
        db.session.add(new_template)
        db.session.commit()
        
        return jsonify({
            'id': new_template.id,
            'name': new_template.name,
            'message': 'AI insight template created successfully'
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating insight template: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/templates/<int:template_id>', methods=['PUT'])
@login_required
def update_template(template_id):
    """Update an existing AI insight template"""
    try:
        template = AiInsightTemplate.query.filter_by(id=template_id, user_id=current_user.id).first()
        
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        
        data = request.json
        
        # Update fields if provided
        if 'name' in data:
            template.name = data['name']
        
        if 'description' in data:
            template.description = data['description']
        
        if 'fields' in data:
            template.set_fields(data['fields'])
        
        if 'model_type' in data:
            template.model_type = data['model_type']
        
        # Save changes
        db.session.commit()
        
        return jsonify({
            'id': template.id,
            'message': 'AI insight template updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating insight template: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/templates/<int:template_id>', methods=['DELETE'])
@login_required
def delete_template(template_id):
    """Delete an AI insight template"""
    try:
        template = AiInsightTemplate.query.filter_by(id=template_id, user_id=current_user.id).first()
        
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        
        # Get associated results
        results = AiInsightResult.query.filter_by(template_id=template_id).all()
        
        # Delete results first
        for result in results:
            db.session.delete(result)
        
        # Delete template
        db.session.delete(template)
        db.session.commit()
        
        return jsonify({
            'message': 'AI insight template deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting insight template: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/analyze', methods=['POST'])
@login_required
def analyze_data():
    """Analyze data using AI insights"""
    try:
        data = request.json
        
        # Get template if specified
        template_id = data.get('template_id')
        template = None
        
        if template_id:
            template = AiInsightTemplate.query.filter_by(id=template_id, user_id=current_user.id).first()
            
            if not template:
                return jsonify({'error': 'Template not found'}), 404
        
        # Get data to analyze
        alert_ids = data.get('alert_ids', [])
        severity_levels = data.get('severity_levels', [])
        time_range = data.get('time_range', '24h')
        custom_prompt = data.get('custom_prompt')
        
        # Choose analysis model
        model_type = data.get('model_type', 'openai')
        if template:
            model_type = template.model_type
        
        # Initialize AI insights
        ai = AIInsights(model_type=model_type)
        
        # Get data to analyze
        opensearch = OpenSearchAPI()
        alerts_data = []
        
        if alert_ids:
            # Get specific alerts by IDs
            for alert_id in alert_ids:
                alert = opensearch.get_alert_by_id(alert_id)
                if 'error' not in alert:
                    alerts_data.append(alert)
        elif severity_levels:
            # Get alerts by severity levels and time range
            end_time = datetime.utcnow().isoformat()
            
            if time_range == '1h':
                start_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            elif time_range == '6h':
                start_time = (datetime.utcnow() - timedelta(hours=6)).isoformat()
            elif time_range == '24h':
                start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()
            elif time_range == '7d':
                start_time = (datetime.utcnow() - timedelta(days=7)).isoformat()
            elif time_range == '30d':
                start_time = (datetime.utcnow() - timedelta(days=30)).isoformat()
            else:
                # Custom time range
                start_time = data.get('start_time')
                end_time = data.get('end_time', end_time)
            
            # Fetch alerts
            results = opensearch.search_alerts(
                severity_levels=severity_levels,
                start_time=start_time,
                end_time=end_time,
                limit=100
            )
            
            if 'error' not in results:
                alerts_data = results.get('results', [])
        else:
            return jsonify({'error': 'No data specified for analysis'}), 400
        
        if not alerts_data:
            return jsonify({'error': 'No alerts found matching criteria'}), 404
        
        # Extract fields if template is specified
        fields = None
        if template:
            fields = template.get_fields()
        
        # Run analysis
        analysis_result = ai.analyze_alerts(
            alerts_data=alerts_data,
            analysis_prompt=custom_prompt,
            fields=fields
        )
        
        if 'error' in analysis_result:
            return jsonify({'error': analysis_result['error']}), 500
        
        # Save result if template is specified
        if template:
            result = AiInsightResult()
            result.template_id = template.id
            result.data_source = json.dumps(alerts_data)
            result.result = analysis_result['analysis']
            
            db.session.add(result)
            db.session.commit()
            
            # Add result ID to response
            analysis_result['result_id'] = result.id
        
        return jsonify(analysis_result)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error analyzing data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/results/<int:result_id>', methods=['GET'])
@login_required
def get_result(result_id):
    """Get a specific analysis result"""
    try:
        # Get result and verify ownership
        result = AiInsightResult.query.join(AiInsightTemplate).filter(
            AiInsightResult.id == result_id,
            AiInsightTemplate.user_id == current_user.id
        ).first()
        
        if not result:
            return jsonify({'error': 'Result not found'}), 404
        
        # Get template
        template = AiInsightTemplate.query.get(result.template_id)
        if not template:
            return jsonify({'error': 'Template not found'}), 404
            
        response = {
            'id': result.id,
            'template_id': result.template_id,
            'template_name': template.name,
            'result': result.result,
            'rating': result.rating,
            'follow_up_questions': result.get_follow_up_questions(),
            'created_at': result.created_at.isoformat(),
            'model_type': template.model_type
        }
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error getting result: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/follow-up', methods=['POST'])
@login_required
def general_follow_up():
    """Ask a follow-up question without a specific saved result"""
    try:
        # Get question and context from request
        data = request.json
        question = data.get('question')
        previous_context = data.get('context')
        
        if not question:
            return jsonify({'error': 'Question is required'}), 400
            
        if not previous_context:
            return jsonify({'error': 'Previous context is required'}), 400
        
        # Initialize AI insights with default model
        ai = AIInsights(model_type='openai')
        
        # Get follow-up answer
        follow_up_result = ai.follow_up_question(
            previous_context=previous_context,
            question=question
        )
        
        if 'error' in follow_up_result:
            return jsonify({'error': follow_up_result['error']}), 500
        
        # Return answer
        return jsonify({
            'question': question,
            'answer': follow_up_result['analysis']
        })
    except Exception as e:
        logger.error(f"Error asking general follow-up: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/api/insights/results/<int:result_id>/follow-up', methods=['POST'])
@login_required
def ask_follow_up(result_id):
    """Ask a follow-up question for an analysis result"""
    try:
        # Get result and verify ownership
        result = AiInsightResult.query.join(AiInsightTemplate).filter(
            AiInsightResult.id == result_id,
            AiInsightTemplate.user_id == current_user.id
        ).first()
        
        if not result:
            return jsonify({'error': 'Result not found'}), 404
        
        # Get question from request
        data = request.json
        question = data.get('question')
        
        if not question:
            return jsonify({'error': 'Question is required'}), 400
        
        # Get template for model type
        template = AiInsightTemplate.query.get(result.template_id)
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        
        # Initialize AI insights with the same model
        ai = AIInsights(model_type=template.model_type)
        
        # Get follow-up answer
        follow_up_result = ai.follow_up_question(
            previous_context=result.result,
            question=question
        )
        
        if 'error' in follow_up_result:
            return jsonify({'error': follow_up_result['error']}), 500
        
        # Save follow-up to result
        result.add_follow_up(question, follow_up_result['analysis'])
        db.session.commit()
        
        # Return updated result
        return jsonify({
            'question': question,
            'answer': follow_up_result['analysis'],
            'follow_up_questions': result.get_follow_up_questions()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error asking follow-up: {str(e)}")
        return jsonify({'error': str(e)}), 500

@insights_bp.route('/insights/analyze_alert', methods=['POST'])
@login_required
def analyze_single_alert():
    """Quick AI analysis for a single alert"""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        index = data.get('index')
        
        if not alert_id:
            return jsonify({'error': 'Alert ID is required'}), 400
            
        opensearch = OpenSearchAPI()
        alert = opensearch.get_alert_by_id(alert_id, index)
        
        if not alert or 'error' in alert:
            return jsonify({'error': 'Alert not found'}), 404
            
        # Initialize AI insights using system default provider (with automatic fallback)
        ai = AIInsights()
        
        # Build prompt for summary
        alert_source = alert.get('_source', alert) if isinstance(alert, dict) else {}
        if not alert_source and hasattr(alert, 'source'):
            alert_source = alert.source
            
        description = alert_source.get('rule', {}).get('description', 'Unknown')
        full_log = alert_source.get('full_log', '')
        if not full_log and 'data' in alert_source:
             full_log = json.dumps(alert_source.get('data'))

        prompt = f"Summarize this security alert in short. What is the purpose of this alert and why was it generated? Description: {description}. Details: {full_log}"
        
        analysis_result = ai.analyze_alerts(
            alerts_data=[alert],
            analysis_prompt=prompt
        )
        
        return jsonify(analysis_result)
    except Exception as e:
        logger.error(f"Error in single alert analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500


@insights_bp.route('/api/insights/voice-qa', methods=['POST'])
@login_required
def voice_qa():
    """
    AI-powered Q&A engine with full access to Wazuh/OpenSearch modules.
    Detects query intent and fetches pre-aggregated data from the right source
    so the AI always has exact, structured answers — not just raw sample records.
    """
    try:
        data = request.json
        question = data.get('question')
        include_context = data.get('include_context', True)
        model_type = data.get('model_type', 'openai')

        if not question:
            return jsonify({'error': 'Question is required', 'success': False}), 400

        ai = AIInsights(model_type=model_type)
        context_data_for_ai = None
        alert_rows     = []
        total_matching = 0

        if include_context:
            try:
                opensearch = OpenSearchAPI()
                q_lower = question.lower()

                # ── 1. Resolve time window ─────────────────────────────────────
                days_match = re.search(r'last\s+(\d+)\s+days?', q_lower)
                hours_match = re.search(r'last\s+(\d+)\s+hours?', q_lower)
                if days_match:
                    delta = timedelta(days=int(days_match.group(1)))
                elif hours_match:
                    delta = timedelta(hours=int(hours_match.group(1)))
                elif any(w in q_lower for w in ['last hour', 'past hour']):
                    delta = timedelta(hours=1)
                elif any(w in q_lower for w in ['today', 'last 24', '24 hours', '24h']):
                    delta = timedelta(hours=24)
                elif any(w in q_lower for w in ['week', 'last 7', '7 days']):
                    delta = timedelta(days=7)
                elif any(w in q_lower for w in ['month', 'last 30', '30 days']):
                    delta = timedelta(days=30)
                elif any(w in q_lower for w in ['90 days', 'quarter']):
                    delta = timedelta(days=90)
                else:
                    delta = timedelta(hours=24)   # default

                end_time   = datetime.utcnow().isoformat()
                start_time = (datetime.utcnow() - delta).isoformat()
                time_label = str(delta)

                # ── 2. Detect severity keywords ────────────────────────────────
                detected_severities = []
                for sev in ['critical', 'high', 'medium', 'low']:
                    if sev in q_lower:
                        detected_severities.append(sev)
                if 'moderate' in q_lower and 'medium' not in detected_severities:
                    detected_severities.append('medium')

                # ── 3. Detect intent flags ─────────────────────────────────────
                intent_system  = any(w in q_lower for w in [
                    'which system', 'which machine', 'which computer', 'which server',
                    'which endpoint', 'which agent', 'which host',
                    'top system', 'top machine', 'top computer', 'top server',
                    'top endpoint', 'top agent', 'most alert', 'most high',
                    'most critical', 'generating', 'from which', 'what system',
                    'what machine', 'what agent', 'what server', 'what computer',
                    'affected system', 'affected machine', 'affected agent',
                    'where', 'source', 'origin',
                ])
                intent_rule    = any(w in q_lower for w in [
                    'which rule', 'what rule', 'top rule', 'rule trigger',
                    'most common rule', 'rule id', 'detection rule',
                ])
                intent_threat  = any(w in q_lower for w in [
                    'threat type', 'attack type', 'threat category', 'kind of attack',
                    'type of threat', 'attack vector', 'threat group',
                ])
                intent_agents  = any(w in q_lower for w in [
                    'agent list', 'list of agent', 'registered agent',
                    'all agent', 'endpoint list', 'monitored machine',
                    'connected agent', 'active agent', 'disconnected agent',
                    'agent status', 'agent info',
                ])
                intent_rules   = any(w in q_lower for w in [
                    'rule list', 'list of rule', 'all rule',
                    'available rule', 'wazuh rule',
                ])
                intent_sca     = any(w in q_lower for w in [
                    'sca', 'compliance', 'policy check', 'configuration assessment',
                    'cis benchmark', 'policy pass', 'policy fail',
                ])

                # Specific agent/IP mentioned directly
                specific_agent_match = re.findall(r'\b([A-Za-z0-9][\w\-]{2,})\b', question)
                ip_matches = re.findall(
                    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', question)
                username_matches = re.findall(
                    r'\b(?:user|account|username)[\s]*:?\s*([a-zA-Z0-9._-]+)\b',
                    question, re.IGNORECASE)
                if not username_matches:
                    username_matches = re.findall(
                        r'\b([a-zA-Z0-9]+[._-][a-zA-Z0-9._-]+)\b', question)

                alert_summary = ""

                # ── 4a. Always fetch exact per-severity counts ─────────────────
                try:
                    counts_result = opensearch.get_alert_count_by_severity(
                        start_time=start_time, end_time=end_time)
                    if 'error' not in counts_result:
                        sc = counts_result
                        total_all = (sc.get('critical', 0) + sc.get('high', 0) +
                                     sc.get('medium', 0) + sc.get('low', 0))
                        alert_summary += (
                            "=== AUTHORITATIVE ALERT COUNTS (exact, from OpenSearch) ===\n"
                            f"Period: last {time_label} ({start_time} → {end_time})\n"
                            f"  Critical : {sc.get('critical', 0)}\n"
                            f"  High     : {sc.get('high', 0)}\n"
                            f"  Medium   : {sc.get('medium', 0)}\n"
                            f"  Low      : {sc.get('low', 0)}\n"
                            f"  FIM      : {sc.get('fim', 0)}\n"
                            f"  Misc     : {sc.get('events', 0)}\n"
                            f"  TOTAL (excl misc/FIM): {total_all}\n"
                            "Always use these exact numbers for count questions.\n"
                            "=== END COUNTS ===\n\n"
                        )
                except Exception as _e:
                    logger.warning(f"severity counts error: {_e}")

                # ── 4b. Per-agent breakdown (when system/agent intent detected) ─
                if intent_system or intent_agents:
                    try:
                        agg = opensearch.get_alerts_by_agent(
                            severity_levels=detected_severities or None,
                            start_time=start_time, end_time=end_time, limit=25)
                        if 'error' not in agg and agg.get('agents'):
                            alert_summary += "=== TOP SYSTEMS BY ALERT COUNT ===\n"
                            alert_summary += f"{'Rank':<5} {'Agent Name':<30} {'IP':<16} {'Total':>7} {'Crit':>6} {'High':>6} {'Med':>6} {'Low':>6}  Top Triggered Rules\n"
                            alert_summary += "-" * 110 + "\n"
                            for i, ag in enumerate(agg['agents'], 1):
                                rules_str = " | ".join(ag['top_rules'][:2]) if ag['top_rules'] else "—"
                                alert_summary += (
                                    f"{i:<5} {ag['agent_name']:<30} {ag['agent_ip']:<16}"
                                    f" {ag['total']:>7} {ag['critical']:>6} {ag['high']:>6}"
                                    f" {ag['medium']:>6} {ag['low']:>6}  {rules_str}\n"
                                )
                            alert_summary += "=== END SYSTEM BREAKDOWN ===\n\n"
                    except Exception as _e:
                        logger.warning(f"agent breakdown error: {_e}")

                # ── 4c. Per-rule breakdown ─────────────────────────────────────
                if intent_rule:
                    try:
                        rule_agg = opensearch.get_alerts_by_rule(
                            severity_levels=detected_severities or None,
                            start_time=start_time, end_time=end_time, limit=20)
                        if 'error' not in rule_agg and rule_agg.get('rules'):
                            alert_summary += "=== TOP TRIGGERED RULES ===\n"
                            for i, r in enumerate(rule_agg['rules'], 1):
                                agents_str = ", ".join(r['agents'][:4]) if r['agents'] else "—"
                                alert_summary += (
                                    f"{i}. Rule {r['rule_id']} (Level {r['level']}) — "
                                    f"{r['description']} | Count: {r['count']} | "
                                    f"Agents: {agents_str}\n"
                                )
                            alert_summary += "=== END RULES ===\n\n"
                    except Exception as _e:
                        logger.warning(f"rule breakdown error: {_e}")

                # ── 4d. Threat type / attack category breakdown ────────────────
                if intent_threat:
                    try:
                        threat = opensearch.get_high_severity_by_threat_type(
                            start_time=start_time, end_time=end_time)
                        if 'error' not in threat:
                            alert_summary += "=== THREAT TYPE BREAKDOWN (High+Critical) ===\n"
                            for tt in threat.get('threat_types', []):
                                alert_summary += f"  {tt['name']}: {tt['count']} alerts\n"
                            alert_summary += "\nLocation breakdown:\n"
                            for loc in threat.get('locations', []):
                                alert_summary += f"  {loc['name']}: {loc['count']} alerts\n"
                            alert_summary += "=== END THREAT TYPES ===\n\n"
                    except Exception as _e:
                        logger.warning(f"threat type error: {_e}")

                # ── 4e. Wazuh Agent list ───────────────────────────────────────
                if intent_agents and not intent_system:
                    try:
                        from wazuh_api import WazuhAPI
                        wazuh = WazuhAPI()
                        agents_resp = wazuh.get_agents({'limit': 100, 'select': 'id,name,ip,status,os.name,lastKeepAlive,group'})
                        agent_list = (agents_resp.get('data', {}) or {}).get('affected_items', [])
                        if agent_list:
                            alert_summary += f"=== WAZUH REGISTERED AGENTS ({len(agent_list)} total) ===\n"
                            for ag in agent_list[:50]:
                                os_name = (ag.get('os') or {}).get('name', 'N/A')
                                grp = ', '.join(ag.get('group', []) or []) or 'default'
                                alert_summary += (
                                    f"  [{ag.get('id')}] {ag.get('name')} | IP: {ag.get('ip', 'N/A')} | "
                                    f"Status: {ag.get('status')} | OS: {os_name} | Group: {grp} | "
                                    f"Last seen: {ag.get('lastKeepAlive', 'N/A')}\n"
                                )
                            alert_summary += "=== END AGENTS ===\n\n"
                    except Exception as _e:
                        logger.warning(f"wazuh agents error: {_e}")

                # ── 4f. Wazuh Rules list ───────────────────────────────────────
                if intent_rules:
                    try:
                        from wazuh_api import WazuhAPI
                        wazuh = WazuhAPI()
                        rules_resp = wazuh.get_rules({'limit': 50, 'level': '12-15'})
                        rule_list = (rules_resp.get('data', {}) or {}).get('affected_items', [])
                        if rule_list:
                            alert_summary += f"=== WAZUH HIGH/CRITICAL RULES (top {len(rule_list)}) ===\n"
                            for r in rule_list[:30]:
                                alert_summary += (
                                    f"  Rule {r.get('id')} | Level {r.get('level')} | "
                                    f"{r.get('description', 'N/A')} | "
                                    f"Groups: {', '.join(r.get('groups', []))}\n"
                                )
                            alert_summary += "=== END RULES ===\n\n"
                    except Exception as _e:
                        logger.warning(f"wazuh rules error: {_e}")

                # ── 4g. Alert records – build OpenSearch filter from the question ─
                #
                # Priority order:
                #  1. Known security-term aliases  (FIM → rule.id, RDP → expanded synonyms…)
                #  2. Explicit IP address
                #  3. Quoted phrase in the question
                #  4. username (dot-separated word)
                #  5. Agent hostname pattern  (DESKTOP-RBF901, SERVER-DC01 …)
                #  6. Remaining meaningful keywords after stop-word removal
                #  (nothing) → rely on severity + time filters only
                #
                additional_filters = {}

                # ── Known security term → OpenSearch mapping ──────────────────
                # Maps lowercase trigger phrase → what to actually pass to search_alerts.
                # Values starting with "RULE_IDS:" use rule.id filter instead of text search.
                # ALL other values must be plain strings (no OR/AND/quotes) — they are
                # passed into multi_match + query_string in search_alerts, which do NOT
                # accept Lucene boolean operators here.
                _SECURITY_ALIASES = {
                    # FIM / File Integrity Monitoring — use exact rule IDs
                    'fim':                      'RULE_IDS:553,554',
                    'file integrity monitoring':'RULE_IDS:553,554',
                    'file integrity':           'RULE_IDS:553,554',
                    'integrity checksum':       'Integrity checksum',
                    'syscheck':                 'syscheck',
                    # Authentication / login
                    'remote desktop':           'Remote Desktop',
                    'rdp':                      'rdp',    # opensearch_api.py expands rdp automatically
                    'ssh':                      'ssh',
                    'brute force':              'brute force',
                    'brute-force':              'brute force',
                    'multiple authentication':  'Multiple authentication failures',
                    'authentication failure':   'authentication failure',
                    'login failure':            'authentication failure',
                    'logon failure':            'logon failure',
                    'failed login':             'authentication failure',
                    'failed logon':             'authentication failure',
                    # Malware / persistence
                    'malware':                  'malware',   # opensearch_api.py expands malware
                    'ransomware':               'ransomware',
                    'trojan':                   'trojan',
                    'persistence':              'persistence', # opensearch_api.py expands persistence
                    'rootkit':                  'rootkit',
                    # Privilege escalation
                    'privilege escalation':     'privilege escalation', # opensearch_api.py expands
                    'sudo':                     'sudo',
                    'uac':                      'User Account Control',
                    # Network threats
                    'port scan':                'port scan',
                    'network scan':             'network scan',
                    'sql injection':            'SQL injection',
                    'web attack':               'web attack',
                    'xss':                      'XSS',
                    # Windows endpoint protection
                    'microsoft defender':       'Microsoft Defender',
                    'windows defender':         'Windows Defender',
                    'defender':                 'Windows Defender',
                    'powershell':               'PowerShell',
                    'wmi':                      'WMI',
                    'registry':                 'registry',
                    'event log':                'event log',
                    'audit failure':            'audit failure',
                    'windows event':            'Windows event',
                    'windows audit':            'Windows audit',
                    'iis':                      'IIS',
                    # Network appliances
                    'sonicwall':                'SonicWall',
                    'firewall':                 'firewall',  # opensearch_api.py expands firewall/network
                    'vpn':                      'VPN',
                    # Vulnerability / SCA
                    'sca':                      'Security Configuration Assessment',
                    'vulnerability':            'vulnerability',
                    'cve':                      'CVE',
                    'patch':                    'patch',
                    # Lateral movement / credential attacks
                    'lateral movement':         'lateral movement',
                    'pass the hash':            'pass the hash',
                    'mimikatz':                 'mimikatz',
                    # Data exfiltration / recon
                    'exfiltration':             'exfiltration',
                    'reconnaissance':           'reconnaissance',
                }

                # ── Helper: stop-word set ──────────────────────────────────────
                _STOP = {
                    'show','me','find','search','list','get','give','display',
                    'fetch','retrieve','return','provide','tell','what','which',
                    'how','many','all','any','some','the','a','an','is','are',
                    'was','were','have','has','been','be','do','does','did',
                    'will','would','can','could','should','may','might',
                    'alert','alerts','event','events','log','logs','record','records',
                    'detail','details','information','info','data','result','results',
                    'security','incident','incidents','issue','issues',
                    'critical','high','medium','moderate','low','severity','level',
                    'last','past','today','yesterday','recent','latest','current',
                    'hour','hours','day','days','week','weeks','month','months',
                    'year','years','24h','7d','30d','90d',
                    'in','on','at','by','to','for','from','of','with','about',
                    'and','or','not','but','if','that','this','these','those',
                    'within','during','since','between','over','under',
                    'related','type','types','kind','associated','triggered','generated',
                }

                def _resolve_filter(q):
                    """
                    Return (filter_type, filter_value):
                      filter_type = 'rule_ids' | 'search_query' | None
                    """
                    q_l = q.lower()

                    # Check multi-word aliases first (longest match wins)
                    for alias in sorted(_SECURITY_ALIASES, key=len, reverse=True):
                        if alias in q_l:
                            val = _SECURITY_ALIASES[alias]
                            if val.startswith('RULE_IDS:'):
                                ids = [int(x) for x in val[9:].split(',')]
                                return ('rule_ids', ids)
                            return ('search_query', val)

                    # Specific IP address
                    ips = re.findall(
                        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', q)
                    if ips:
                        return ('search_query', ' OR '.join(ips))

                    # Explicit quoted phrase
                    qm = re.search(r'"([^"]{3,})"', q)
                    if qm:
                        return ('search_query', f'"{qm.group(1)}"')

                    # username (dot/hyphen-separated word like umair.farooq)
                    um = re.findall(
                        r'\b([a-zA-Z][a-zA-Z0-9]*[._-][a-zA-Z0-9._-]+)\b', q)
                    if um:
                        return ('search_query', f'"{um[0]}"')

                    # Hostname/agent pattern (DESKTOP-RBF901, SERVER-DC01)
                    hm = re.search(
                        r'\b([A-Z][A-Z0-9]{2,}-[A-Z0-9]{2,}(?:-[A-Z0-9]+)*)\b',
                        q, re.IGNORECASE)
                    if hm:
                        return ('search_query', hm.group(1))

                    # Remaining meaningful words after stop-word removal
                    # Allow ≥3-char tokens (so FIM, RDP, SSH survive)
                    tokens = re.sub(r'[^\w\s]', ' ', q).split()
                    kept = [t for t in tokens
                            if t.lower() not in _STOP
                            and len(t) >= 3
                            and not t.isdigit()]
                    if kept:
                        # Pass as plain space-joined string — the multi_match in
                        # search_alerts handles multi-word queries correctly.
                        return ('search_query', ' '.join(kept))

                    return (None, None)

                f_type, f_val = _resolve_filter(question)
                if f_type == 'rule_ids':
                    additional_filters['rule.id'] = f_val
                elif f_type == 'search_query':
                    additional_filters['search_query'] = f_val

                sample_results = opensearch.search_alerts(
                    start_time=start_time,
                    end_time=end_time,
                    limit=100,
                    severity_levels=detected_severities if detected_severities else None,
                    additional_filters=additional_filters,
                )

                alert_rows = []       # structured rows returned to the frontend
                total_matching = 0

                if sample_results and 'error' not in sample_results:
                    raw_hits = sample_results.get('results', [])
                    total_matching = sample_results.get('total', len(raw_hits))

                    for hit in raw_hits:
                        source  = hit.get('source', hit.get('_source', {}))
                        ag      = source.get('agent', {}) or {}
                        rule    = source.get('rule',  {}) or {}
                        level   = rule.get('level', 0)
                        if level >= 15:
                            sev = 'critical'
                        elif level >= 12:
                            sev = 'high'
                        elif level >= 7:
                            sev = 'medium'
                        else:
                            sev = 'low'
                        alert_rows.append({
                            'id':          hit.get('id', ''),
                            'index':       hit.get('index', ''),
                            'timestamp':   source.get('@timestamp', ''),
                            'severity':    sev,
                            'level':       level,
                            'agent_name':  ag.get('name', 'N/A'),
                            'agent_ip':    ag.get('ip',   'N/A'),
                            'rule_id':     rule.get('id',          'N/A'),
                            'rule_desc':   rule.get('description', 'N/A'),
                            'rule_groups': rule.get('groups', []),
                            'location':    (ag.get('labels') or {}).get('location', {}).get('set', ''),
                        })

                    # Feed a compact text summary to the AI (not raw JSON)
                    if alert_rows:
                        shown = min(20, len(alert_rows))
                        alert_summary += (
                            f"=== ALERT RECORDS (Total matching: {total_matching},"
                            f" showing top {shown}) ===\n"
                        )
                        for idx, r in enumerate(alert_rows[:shown], 1):
                            alert_summary += (
                                f"#{idx} [{r['severity'].upper()}] {r['agent_name']} ({r['agent_ip']}) | "
                                f"Rule {r['rule_id']} Lvl {r['level']} — {r['rule_desc']} | {r['timestamp']}\n"
                            )
                        alert_summary += "=== END RECORDS ===\n\n"

                context_data_for_ai = alert_summary if alert_summary.strip() else None

            except Exception as e:
                logger.error(f"Error fetching alert context: {str(e)}")
                context_data_for_ai = None
                alert_rows = []
                total_matching = 0

        # ── 5. Get the answer ──────────────────────────────────────────────────
        result = ai.ask_wazuh_question(
            question=question,
            context_data=context_data_for_ai
        )

        if 'error' in result:
            return jsonify({'success': False, 'error': result['error']}), 500

        return jsonify({
            'success':       True,
            'question':      question,
            'answer':        result.get('answer'),
            'summary':       result.get('summary'),
            'model':         result.get('model'),
            'provider':      result.get('provider'),
            'alerts':        alert_rows,
            'total_alerts':  total_matching,
        })
    except Exception as e:
        logger.error(f"Error in voice-qa: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500
