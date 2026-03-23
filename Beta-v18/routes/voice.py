import logging
from flask import Blueprint, request, jsonify, g
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

voice_bp = Blueprint('voice', __name__, url_prefix='/api/voice')

@voice_bp.route('/transcribe', methods=['POST'])
@login_required
def transcribe_audio():
    """
    Transcribe audio to text using OpenAI Whisper.
    
    Expects JSON with:
    - audio_data: Base64 encoded audio
    - format: Audio format (webm, wav, mp3)
    """
    from voice_commands import voice_processor
    
    try:
        data = request.get_json()
        
        if not data or 'audio_data' not in data:
            return jsonify({"error": "No audio data provided", "success": False}), 400
        
        audio_data = data['audio_data']
        audio_format = data.get('format', 'webm')
        
        if ',' in audio_data:
            audio_data = audio_data.split(',')[1]
        
        result = voice_processor.transcribe_audio(audio_data, audio_format)
        
        logger.info(f"Voice transcription for user {current_user.username}: {result.get('text', 'N/A')[:50]}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in transcribe_audio: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@voice_bp.route('/process', methods=['POST'])
@login_required
def process_command():
    """
    Process a voice command text and return the action to take.
    
    Expects JSON with:
    - text: The command text (from transcription or typed)
    """
    from voice_commands import voice_processor
    
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({"error": "No command text provided", "success": False}), 400
        
        text = data['text']
        user_role = current_user.role if hasattr(current_user, 'role') else 'user'
        
        result = voice_processor.process_command(text, user_role)
        
        logger.info(f"Voice command from {current_user.username} (role: {user_role}): '{text}' -> intent: {result.get('intent')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in process_command: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@voice_bp.route('/execute', methods=['POST'])
@login_required
def execute_command():
    """
    Execute a voice command action and return results.
    
    Expects JSON with:
    - intent: The command intent to execute
    - parameters: Any parameters for the command
    """
    from voice_commands import voice_processor
    
    try:
        data = request.get_json()
        
        if not data or 'intent' not in data:
            return jsonify({"error": "No intent provided", "success": False}), 400
        
        intent = data['intent']
        parameters = data.get('parameters', {})
        user_role = current_user.role if hasattr(current_user, 'role') else 'user'
        
        if not voice_processor.check_permission(intent, user_role):
            return jsonify({
                "success": False,
                "error": "Permission denied",
                "response_text": "You don't have permission to execute this command."
            }), 403
        
        result = _execute_intent(intent, parameters)
        
        logger.info(f"Voice command executed by {current_user.username}: {intent}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in execute_command: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


def _execute_intent(intent, parameters):
    """Execute a specific intent and return results."""
    from opensearch_api import OpenSearchAPI
    from wazuh_api import WazuhAPI
    from ai_insights import AIInsights
    from datetime import datetime, timedelta
    
    try:
        if intent == "get_stats":
            api = OpenSearchAPI()
            wazuh = WazuhAPI()
            
            days = parameters.get('days', 1)
            end_time = datetime.utcnow().isoformat()
            start_time = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            alert_counts = api.get_alert_count_by_severity(start_time=start_time, end_time=end_time)
            agents_status = wazuh.get_agents({"limit": 500})
            
            agent_stats = {'total': 0, 'active': 0, 'disconnected': 0}
            if agents_status and 'data' in agents_status and 'affected_items' in agents_status['data']:
                agents = agents_status['data']['affected_items']
                agent_stats['total'] = len(agents)
                for agent in agents:
                    status = agent.get('status', '')
                    if status == 'active':
                        agent_stats['active'] += 1
                    elif status == 'disconnected':
                        agent_stats['disconnected'] += 1
            
            if alert_counts:
                response_text = f"Dashboard summary: {alert_counts.get('critical', 0)} critical alerts, " \
                              f"{alert_counts.get('high', 0)} high, {alert_counts.get('medium', 0)} medium, " \
                              f"and {alert_counts.get('low', 0)} low severity alerts. " \
                              f"{agent_stats.get('active', 0)} agents are currently active out of {agent_stats.get('total', 0)} total."
                
                return {
                    "success": True,
                    "data": {"alert_counts": alert_counts, "agent_stats": agent_stats},
                    "response_text": response_text
                }
            else:
                return {
                    "success": False,
                    "error": "Unable to fetch statistics",
                    "response_text": "I couldn't retrieve the dashboard statistics. Please check your OpenSearch connection."
                }
        
        elif intent == "get_critical_alerts":
            api = OpenSearchAPI()
            end_time = datetime.utcnow().isoformat()
            start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()
            
            result = api.search_alerts(
                severity_levels=['critical', 'high'],
                start_time=start_time,
                end_time=end_time,
                limit=10
            )
            
            alerts = result.get('results', []) if result else []
            
            if alerts:
                count = len(alerts)
                first_alert = alerts[0].get('source', {}) if alerts else {}
                rule_desc = first_alert.get('rule', {}).get('description', 'Unknown alert')
                response_text = f"Found {count} critical and high severity alerts. " \
                              f"The most recent is: {rule_desc}"
                
                return {
                    "success": True,
                    "data": {"alerts": alerts, "count": count},
                    "response_text": response_text
                }
            else:
                return {
                    "success": True,
                    "data": {"alerts": [], "count": 0},
                    "response_text": "Good news! There are no critical or high severity alerts at this time."
                }
        
        elif intent == "get_agent_status":
            wazuh = WazuhAPI()
            agents_status = wazuh.get_agents({"limit": 500})
            
            agent_stats = {'total': 0, 'active': 0, 'disconnected': 0}
            if agents_status and 'data' in agents_status and 'affected_items' in agents_status['data']:
                agents = agents_status['data']['affected_items']
                agent_stats['total'] = len(agents)
                for agent in agents:
                    status = agent.get('status', '')
                    if status == 'active':
                        agent_stats['active'] += 1
                    elif status == 'disconnected':
                        agent_stats['disconnected'] += 1
            
            response_text = f"Agent status: {agent_stats.get('active', 0)} active, " \
                          f"{agent_stats.get('disconnected', 0)} disconnected, " \
                          f"{agent_stats.get('total', 0)} total agents."
            
            return {
                "success": True,
                "data": agent_stats,
                "response_text": response_text
            }
        
        elif intent == "analyze_alerts":
            api = OpenSearchAPI()
            end_time = datetime.utcnow().isoformat()
            start_time = (datetime.utcnow() - timedelta(days=1)).isoformat()
            
            result = api.search_alerts(
                start_time=start_time,
                end_time=end_time,
                limit=20
            )
            
            alerts = result.get('results', []) if result else []
            
            if alerts:
                ai = AIInsights(model_type="openai")
                analysis = ai.analyze_alerts(alerts)
                
                if 'error' not in analysis:
                    return {
                        "success": True,
                        "data": analysis,
                        "response_text": "I've analyzed the recent alerts. " + analysis.get('analysis', '')[:200] + "..."
                    }
                else:
                    return {
                        "success": False,
                        "error": analysis['error'],
                        "response_text": "I couldn't complete the analysis. Please check your AI configuration."
                    }
            else:
                return {
                    "success": True,
                    "data": {},
                    "response_text": "There are no recent alerts to analyze."
                }
        
        elif intent == "help":
            from voice_commands import voice_processor
            help_text = voice_processor.get_help_text()
            
            return {
                "success": True,
                "data": {"commands": list(voice_processor.SUPPORTED_COMMANDS.keys())},
                "response_text": help_text
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown intent: {intent}",
                "response_text": "I don't know how to execute that command."
            }
            
    except Exception as e:
        logger.error(f"Error executing intent {intent}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "response_text": f"An error occurred while executing the command: {str(e)}"
        }


@voice_bp.route('/speak', methods=['POST'])
@login_required
def text_to_speech():
    """
    Convert text to speech using OpenAI TTS.
    
    Expects JSON with:
    - text: The text to convert to speech
    """
    from voice_commands import voice_processor
    
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({"error": "No text provided", "success": False}), 400
        
        text = data['text']
        
        result = voice_processor.text_to_speech_data(text)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in text_to_speech: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@voice_bp.route('/status', methods=['GET'])
@login_required
def voice_status():
    """Check if voice commands are available and configured."""
    from voice_commands import voice_processor, VoiceCommandProcessor
    
    openai_configured = voice_processor.openai is not None
    
    return jsonify({
        "success": True,
        "voice_enabled": openai_configured,
        "stt_available": openai_configured,
        "tts_available": openai_configured,
        "fallback_available": True,
        "supported_commands": list(VoiceCommandProcessor.SUPPORTED_COMMANDS.keys())
    })
