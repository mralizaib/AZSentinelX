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
    AI-powered search Q&A for security alerts and Wazuh data.
    Trained on real-time Wazuh/OpenSearch data and historical patterns.
    """
    try:
        data = request.json
        question = data.get('question')
        include_context = data.get('include_context', True)
        model_type = data.get('model_type', 'openai')
        
        if not question:
            return jsonify({'error': 'Question is required', 'success': False}), 400
        
        # Initialize AI insights
        ai = AIInsights(model_type=model_type)
        
        # Get context data from OpenSearch (real-time Wazuh data)
        context_data = []
        context_count = 0
        
        if include_context:
            try:
                opensearch = OpenSearchAPI()
                
                # Check for explicit day counts
                days_match = re.search(r'last (\d+) days', question.lower())
                if days_match:
                    num_days = int(days_match.group(1))
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=num_days)).isoformat()
                elif 'last 90 days' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=90)).isoformat()
                elif 'last 20 days' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=20)).isoformat()
                elif 'last 10 days' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=10)).isoformat()
                elif 'last 1 hour' in question.lower() or 'last hour' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()
                elif 'today' in question.lower() or 'last 24' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(hours=24)).isoformat()
                elif 'last 7' in question.lower() or 'week' in question.lower() or '7 days' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=7)).isoformat()
                elif 'last 30' in question.lower() or 'month' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=30)).isoformat()
                else:
                    # Default to last 24 hours
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(hours=24)).isoformat()
                
                # Build additional filters
                additional_filters = {}
                
                # Check for file extensions
                ext_match = re.search(r'\.([a-zA-Z0-9]{3,4})\b', question.lower())
                if ext_match:
                    extension = ext_match.group(1)
                    additional_filters['search_query'] = f"*{extension}*"
                
                # Check for agent name
                agent_pattern = r'([A-Z]{2,4}\d+-\d{2}-\d{2})'
                agent_matches = re.findall(agent_pattern, question)
                if agent_matches:
                    additional_filters['agent.name'] = agent_matches[0]
                
                # Check for IP
                ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                ip_matches = re.findall(ip_pattern, question)
                if ip_matches:
                    additional_filters['search_query'] = ' OR '.join(ip_matches)
                
                # Check for username
                username_pattern = r'\b(?:user|account|username)[\s]*:?\s*([a-zA-Z0-9._-]+)\b'
                username_matches = re.findall(username_pattern, question, re.IGNORECASE)
                if not username_matches:
                    standalone_username_pattern = r'\b([a-zA-Z0-9]+[._-][a-zA-Z0-9._-]+)\b'
                    username_matches = re.findall(standalone_username_pattern, question, re.IGNORECASE)
                
                if username_matches:
                    additional_filters['search_query'] = f'"{username_matches[0]}"'
                
                if not additional_filters:
                    search_query = question.replace('Show me', '').replace('alerts', '').replace("'s", '').strip()
                    additional_filters['search_query'] = search_query
                
                # Fetch alerts
                results = opensearch.search_alerts(
                    start_time=start_time,
                    end_time=end_time,
                    limit=300,
                    additional_filters=additional_filters
                )
                
                if results and 'error' not in results:
                    alerts = results.get('results', [])
                    context_data = [alert.get('source', alert.get('_source', alert)) for alert in alerts]
                    context_count = len(alerts)
                else:
                    context_data = []
                    context_count = 0
                
                # Format alerts summary including full_log
                if context_data and context_count > 0:
                    alert_summary = f"=== SECURITY ALERT DATA (Found {context_count} total alerts) ===\n\n"
                    for idx, source in enumerate(context_data[:30], 1):
                        agent = source.get('agent', {})
                        rule = source.get('rule', {})
                        timestamp = source.get('@timestamp', '')
                        data = source.get('data', {})
                        syscheck = source.get('syscheck', {})
                        full_log = source.get('full_log', '')
                        
                        log_content = full_log if full_log else json.dumps(data)
                        
                        alert_summary += f"ALERT #{idx}\n"
                        alert_summary += f"  - Event: {rule.get('id', 'N/A')} - {rule.get('description', 'No description')}\n"
                        alert_summary += f"  - Computer/Agent: {agent.get('name', 'Unknown')} (IP: {agent.get('ip', 'N/A')})\n"
                        alert_summary += f"  - Timestamp: {timestamp}\n"
                        if syscheck.get('path'):
                            alert_summary += f"  - File Path: {syscheck.get('path')}\n"
                        alert_summary += f"  - FULL LOG: {log_content}\n"
                        alert_summary += "-" * 30 + "\n"
                    context_data_for_ai = alert_summary
                else:
                    context_data_for_ai = None
                
            except Exception as e:
                logger.error(f"Error fetching alert context: {str(e)}")
                context_data_for_ai = None
        
        # Get the answer
        result = ai.ask_wazuh_question(
            question=question,
            context_data=context_data_for_ai
        )
        
        if 'error' in result:
            return jsonify({'success': False, 'error': result['error']}), 500
        
        return jsonify({
            'success': True,
            'question': question,
            'answer': result.get('answer'),
            'summary': result.get('summary'),
            'model': result.get('model'),
            'provider': result.get('provider')
        })
    except Exception as e:
        logger.error(f"Error in voice-qa: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500
