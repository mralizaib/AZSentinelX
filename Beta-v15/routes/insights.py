from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import logging
from datetime import datetime, timedelta
import json
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
        new_template.description = data.get('description', '')
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
            
        # Initialize AI insights
        ai = AIInsights(model_type='openai')
        
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
    Supports questions in ANY language including Punjabi, Urdu, Hindi, English, and more.
    Responds in the SAME language as the user's question.
    
    Expects JSON with:
    - question: The user's question (in any language - English, Hindi, Punjabi, Urdu, etc.)
    - include_context: Whether to include recent alert context (optional)
    - model_type: AI model to use (optional, defaults to 'openai')
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
                
                # Determine time range based on question keywords
                import re
                
                # Check for explicit day counts like "last 10 days"
                days_match = re.search(r'last (\d+) days', question.lower())
                if days_match:
                    num_days = int(days_match.group(1))
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=num_days)).isoformat()
                    logger.info(f"Search time range: last {num_days} days")
                elif 'last 1 hour' in question.lower() or 'last hour' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()
                    logger.info("Search time range: last 1 hour")
                elif 'today' in question.lower() or 'last 24' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(hours=24)).isoformat()
                    logger.info("Search time range: last 24 hours")
                elif 'last 7' in question.lower() or 'week' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=7)).isoformat()
                    logger.info("Search time range: last 7 days")
                elif 'last 30' in question.lower() or 'month' in question.lower():
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(days=30)).isoformat()
                    logger.info("Search time range: last 30 days")
                else:
                    # Default to last 24 hours
                    end_time = datetime.utcnow().isoformat()
                    start_time = (datetime.utcnow() - timedelta(hours=24)).isoformat()
                    logger.info("Search time range: last 24 hours (default)")
                
                # Build additional filters based on question content
                additional_filters = {}
                search_terms = []
                
                # Check for file extensions (e.g., .xlsx, .pdf, .docx, .csv)
                ext_match = re.search(r'\.([a-zA-Z0-9]{3,4})\b', question.lower())
                if ext_match:
                    extension = ext_match.group(1)
                    # We look for the extension in the syscheck path or full_log
                    additional_filters['search_query'] = f"*{extension}*"
                    search_terms.append(f"file_type: {extension}")
                    logger.info(f"Searching for file extension: {extension}")
                
                # Check for agent name in question
                # Common patterns: "BMS5-76-37", "CMS-81-10", "agent name", etc.
                import re
                agent_pattern = r'([A-Z]{2,4}\d+-\d{2}-\d{2})'
                agent_matches = re.findall(agent_pattern, question)
                
                if agent_matches:
                    agent_name = agent_matches[0]
                    additional_filters['agent.name'] = agent_name
                    search_terms.append(f"agent: {agent_name}")
                    logger.info(f"Searching for agent: {agent_name}")
                
                # Check for IP address patterns (IPv4)
                ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                ip_matches = re.findall(ip_pattern, question)
                
                if ip_matches:
                    # Search for IP in source or destination
                    for ip in ip_matches:
                        search_terms.append(f"IP: {ip}")
                    additional_filters['search_query'] = ' OR '.join(ip_matches)
                    logger.info(f"Searching for IPs: {ip_matches}")
                
                # Check for username patterns
                # Support: "user: name", "username name", "account name" AND standalone names with dots/underscores/dashes
                username_pattern = r'\b(?:user|account|username)[\s]*:?\s*([a-zA-Z0-9._-]+)\b'
                username_matches = re.findall(username_pattern, question, re.IGNORECASE)
                
                # If no explicit prefix, look for common username formats (contains dot, underscore, or dash)
                if not username_matches:
                    # Look for things like umair.farooq or umair_farooq or user-123
                    standalone_username_pattern = r'\b([a-zA-Z0-9]+[._-][a-zA-Z0-9._-]+)\b'
                    username_matches = re.findall(standalone_username_pattern, question, re.IGNORECASE)
                
                if username_matches:
                    username = username_matches[0]
                    # Use the username directly for searching across multiple fields
                    # We wrap in quotes for phrase matching in query_string if it contains special chars
                    additional_filters['search_query'] = f'"{username}"'
                    search_terms.append(f"user: {username}")
                    logger.info(f"Searching for username: {username}")
                
                # If NO specific filters were found, use the whole question as a search query
                if not additional_filters:
                    # Clean the question for search_query but keep the core intent
                    search_query = question.replace('Show me', '').replace('alerts', '').replace("'s", '').strip()
                    additional_filters['search_query'] = search_query
                    logger.info(f"No specific filters found, using cleaned question as search query: {search_query}")
                
                # Fetch alerts with filters
                results = opensearch.search_alerts(
                    start_time=start_time,
                    end_time=end_time,
                    limit=300,  # Increased limit for better context
                    additional_filters=additional_filters
                )
                
                if results and 'error' not in results:
                    alerts = results.get('results', [])
                    context_data = alerts
                    context_count = len(alerts)
                    logger.info(f"Retrieved {context_count} alerts from OpenSearch for question: {question[:50]}... Search terms: {search_terms}")
                    
                    # Log if no results found
                    if context_count == 0 and search_terms:
                        logger.warning(f"No alerts found for search terms: {search_terms}")
                    elif context_count > 0:
                        logger.info(f"SUCCESS: Found {context_count} alerts matching criteria")
                else:
                    error_msg = results.get('error', 'Unknown error')
                    logger.warning(f"OpenSearch search error: {error_msg}")
                    logger.warning(f"Search request was: {results.get('request', {})}")
            
            except Exception as e:
                logger.error(f"Error fetching alert context: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
                # Continue without context
        
        # Prepare enhanced context for AI
        if context_data and context_count > 0:
            # Format alerts into a detailed summary including user/IP information
            alert_summary = f"=== SECURITY ALERT DATA (Found {context_count} total alerts) ===\n\n"
            
            # Extract key information from alerts
            for idx, alert in enumerate(context_data[:30], 1):  # Increased to top 30
                # OpenSearchAPI returns with 'source' key, not '_source'
                source = alert.get('source', alert.get('_source', {}))
                agent = source.get('agent', {})
                rule = source.get('rule', {})
                timestamp = source.get('@timestamp', '')
                data = source.get('data', {})
                
                # Include detailed user/IP information if available
                data_win = data.get('win', {})
                eventdata = data_win.get('eventdata', {})
                syscheck = source.get('syscheck', {})
                
                # Try multiple username fields for better identification
                username = (
                    eventdata.get('targetUserName') or
                    eventdata.get('SubjectUserName') or
                    eventdata.get('UserName') or
                    eventdata.get('subjectUserName') or
                    syscheck.get('uname_after') or
                    data.get('user') or
                    "N/A"
                )
                
                source_ip = data.get('srcip') or eventdata.get('SourceAddress')
                dest_ip = data.get('dstip') or eventdata.get('DestinationAddress')
                login_type = eventdata.get('logonType')
                
                alert_summary += f"ALERT #{idx}\n"
                alert_summary += f"  - User Name: {username}\n"
                alert_summary += f"  - Computer/Agent: {agent.get('name', 'Unknown')} (ID: {agent.get('id', 'N/A')}, IP: {agent.get('ip', 'N/A')})\n"
                alert_summary += f"  - IP Activity: Source: {source_ip or 'N/A'}, Destination: {dest_ip or 'N/A'}\n"
                alert_summary += f"  - Event: {rule.get('id', 'N/A')} - {rule.get('description', 'No description')}\n"
                
                if syscheck.get('path'):
                    alert_summary += f"  - File Path: {syscheck.get('path')}\n"
                
                alert_summary += f"  - Severity: {rule.get('level', 'Unknown')}\n"
                alert_summary += f"  - Timestamp: {timestamp}\n"
                alert_summary += "-" * 30 + "\n"
            
            context_data_for_ai = alert_summary
            logger.info(f"Formatted {context_count} alerts into context summary for AI analysis")
        else:
            context_data_for_ai = None
            if context_count == 0:
                logger.warning(f"No alert data found to provide to AI for question: {question[:50]}...")
        
        # Get the answer
        result = ai.ask_wazuh_question(
            question=question,
            context_data=context_data_for_ai
        )
        
        if 'error' in result:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 500
        
        logger.info(f"AI Search from {current_user.username}: '{question[:50]}...' (Alerts found: {context_count})")
        
        return jsonify({
            'success': True,
            'question': question,
            'answer': result.get('answer', ''),
            'summary': result.get('summary', ''),
            'model': result.get('model', ''),
            'provider': result.get('provider', ''),
            'context_size': context_count,
            'alerts_found': context_count
        })
        
    except Exception as e:
        logger.error(f"Error in AI search Q&A: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e), 'success': False}), 500


@insights_bp.route('/api/insights/voice-transcribe', methods=['POST'])
@login_required
def voice_transcribe():
    """
    Transcribe audio for insights voice Q&A.
    Supports all languages (auto-detection).
    
    Expects JSON with:
    - audio_data: Base64 encoded audio
    - format: Audio format (webm, wav, mp3)
    """
    try:
        from voice_commands import voice_processor
        
        data = request.get_json()
        
        if not data or 'audio_data' not in data:
            return jsonify({"error": "No audio data provided", "success": False}), 400
        
        audio_data = data['audio_data']
        audio_format = data.get('format', 'webm')
        
        if ',' in audio_data:
            audio_data = audio_data.split(',')[1]
        
        result = voice_processor.transcribe_audio(audio_data, audio_format)
        
        logger.info(f"Voice transcription for insights Q&A by {current_user.username}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in voice transcribe: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@insights_bp.route('/api/insights/conversation', methods=['GET', 'POST'])
@login_required
def conversation():
    """
    Get or save conversation for session continuity.
    POST: Save a new message to the conversation
    GET: Retrieve the current conversation
    """
    try:
        session_id = request.args.get('session_id') or request.json.get('session_id', '')
        
        if request.method == 'POST':
            data = request.json
            message = data.get('message')
            role = data.get('role', 'user')  # 'user' or 'assistant'
            provider = data.get('provider')
            
            if not message or not session_id:
                return jsonify({'error': 'Message and session_id required'}), 400
            
            # Get or create conversation
            conv = Conversation.query.filter_by(user_id=current_user.id, session_id=session_id).first()
            if not conv:
                conv = Conversation(user_id=current_user.id, session_id=session_id)
                db.session.add(conv)
            
            # Add message
            conv.add_message(role, message, provider)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'conversation_id': conv.id,
                'messages_count': len(conv.get_messages())
            })
        
        else:  # GET
            if not session_id:
                return jsonify({'messages': []})
            
            conv = Conversation.query.filter_by(user_id=current_user.id, session_id=session_id).first()
            if not conv:
                return jsonify({'messages': []})
            
            return jsonify({
                'conversation_id': conv.id,
                'messages': conv.get_messages()
            })
    
    except Exception as e:
        logger.error(f"Error in conversation: {str(e)}")
        return jsonify({'error': str(e)}), 500


@insights_bp.route('/api/insights/conversation/clear', methods=['POST'])
@login_required
def clear_conversation():
    """Clear the current conversation when user closes the window"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'session_id required'}), 400
        
        # Delete conversation
        Conversation.query.filter_by(user_id=current_user.id, session_id=session_id).delete()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Conversation cleared'})
    
    except Exception as e:
        logger.error(f"Error clearing conversation: {str(e)}")
        return jsonify({'error': str(e)}), 500
