import os
import json
import logging
import base64
import tempfile
from config import Config
from openai import OpenAI

logger = logging.getLogger(__name__)

class VoiceCommandProcessor:
    """
    Processes voice commands using OpenAI Whisper for speech-to-text
    and GPT for natural language understanding and intent recognition.
    """
    
    SUPPORTED_COMMANDS = {
        "view_alerts": {
            "description": "View security alerts",
            "examples": ["show me alerts", "view alerts", "display alerts", "what are the current alerts"],
            "action": "navigate",
            "target": "/alerts"
        },
        "view_dashboard": {
            "description": "View main dashboard",
            "examples": ["go to dashboard", "show dashboard", "home", "main page"],
            "action": "navigate",
            "target": "/dashboard"
        },
        "view_reports": {
            "description": "View reports",
            "examples": ["show reports", "view reports", "report page"],
            "action": "navigate",
            "target": "/reports"
        },
        "view_insights": {
            "description": "View AI insights",
            "examples": ["show insights", "ai analysis", "view insights"],
            "action": "navigate",
            "target": "/insights"
        },
        "generate_report": {
            "description": "Generate a security report",
            "examples": ["generate report", "create report", "make a report"],
            "action": "action",
            "requires_confirmation": True
        },
        "analyze_alerts": {
            "description": "Analyze current alerts with AI",
            "examples": ["analyze alerts", "what do you think about the alerts", "security analysis"],
            "action": "action",
            "requires_confirmation": False
        },
        "get_stats": {
            "description": "Get dashboard statistics",
            "examples": ["show stats", "get statistics", "how many alerts", "summary"],
            "action": "query"
        },
        "get_critical_alerts": {
            "description": "Get critical and high severity alerts",
            "examples": ["show critical alerts", "what are the critical issues", "high priority alerts"],
            "action": "query"
        },
        "get_agent_status": {
            "description": "Get agent status information",
            "examples": ["agent status", "how many agents", "connected agents"],
            "action": "query"
        },
        "help": {
            "description": "Show available voice commands",
            "examples": ["help", "what can you do", "available commands"],
            "action": "info"
        }
    }
    
    def __init__(self):
        self.openai = None
        if Config.OPENAI_API_KEY:
            self.openai = OpenAI(api_key=Config.OPENAI_API_KEY)
    
    def transcribe_audio(self, audio_data, audio_format="webm"):
        """
        Transcribe audio data to text using OpenAI Whisper.
        
        Args:
            audio_data: Base64 encoded audio data
            audio_format: Audio format (webm, wav, mp3, etc.)
            
        Returns:
            Dictionary with transcription result
        """
        if not self.openai:
            return {"error": "OpenAI API key not configured", "success": False}
        
        try:
            audio_bytes = base64.b64decode(audio_data)
            
            with tempfile.NamedTemporaryFile(suffix=f".{audio_format}", delete=False) as temp_file:
                temp_file.write(audio_bytes)
                temp_file_path = temp_file.name
            
            try:
                with open(temp_file_path, "rb") as audio_file:
                    response = self.openai.audio.transcriptions.create(
                        model="whisper-1",
                        file=audio_file
                    )
                
                return {
                    "success": True,
                    "text": response.text,
                    "language": "auto"
                }
            finally:
                os.unlink(temp_file_path)
                
        except Exception as e:
            logger.error(f"Error transcribing audio: {str(e)}")
            return {"error": str(e), "success": False}
    
    def process_command(self, text, user_role="user"):
        """
        Process a text command and determine the intent and action.
        
        Args:
            text: The transcribed or typed command text
            user_role: User's role for permission checking
            
        Returns:
            Dictionary with command interpretation and action
        """
        if not self.openai:
            return self._fallback_command_processing(text)
        
        try:
            command_descriptions = "\n".join([
                f"- {cmd}: {info['description']} (examples: {', '.join(info['examples'][:2])})"
                for cmd, info in self.SUPPORTED_COMMANDS.items()
            ])
            
            response = self.openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": f"""You are a voice command interpreter for a security dashboard application called InsightAnalyzer.
Your job is to understand user voice commands and map them to specific actions.

Available commands:
{command_descriptions}

Respond with a JSON object containing:
- "intent": The command identifier (e.g., "view_alerts", "get_stats", etc.)
- "confidence": A number between 0 and 1 indicating your confidence
- "parameters": Any extracted parameters (e.g., time range, severity level)
- "response_text": A brief, friendly response to speak back to the user

If the command is unclear or not supported, use intent "unknown".
Always respond with valid JSON."""
                    },
                    {"role": "user", "content": text}
                ],
                response_format={"type": "json_object"},
                max_tokens=500
            )
            
            content = response.choices[0].message.content
            if not content:
                return self._fallback_command_processing(text)
            result = json.loads(content)
            
            intent = result.get("intent", "unknown")
            if intent in self.SUPPORTED_COMMANDS:
                command_info = self.SUPPORTED_COMMANDS[intent]
                result["action"] = command_info.get("action")
                result["target"] = command_info.get("target")
                result["requires_confirmation"] = command_info.get("requires_confirmation", False)
            
            if not self._check_permission(intent, user_role):
                result["error"] = "You don't have permission to execute this command"
                result["intent"] = "permission_denied"
            
            return {
                "success": True,
                "original_text": text,
                **result
            }
            
        except Exception as e:
            logger.error(f"Error processing command: {str(e)}")
            return self._fallback_command_processing(text)
    
    def _fallback_command_processing(self, text):
        """
        Fallback command processing when OpenAI is not available.
        Uses simple keyword matching.
        """
        text_lower = text.lower().strip()
        
        keyword_mapping = {
            "view_alerts": ["alert", "alerts", "show alert"],
            "view_dashboard": ["dashboard", "home", "main"],
            "view_reports": ["report", "reports"],
            "view_insights": ["insight", "insights", "analysis"],
            "generate_report": ["generate report", "create report"],
            "analyze_alerts": ["analyze", "analyse"],
            "get_stats": ["stat", "statistics", "summary", "how many"],
            "get_critical_alerts": ["critical", "high priority", "urgent"],
            "get_agent_status": ["agent", "agents"],
            "help": ["help", "what can you do", "commands"]
        }
        
        for intent, keywords in keyword_mapping.items():
            for keyword in keywords:
                if keyword in text_lower:
                    command_info = self.SUPPORTED_COMMANDS.get(intent, {})
                    return {
                        "success": True,
                        "original_text": text,
                        "intent": intent,
                        "confidence": 0.7,
                        "parameters": {},
                        "action": command_info.get("action"),
                        "target": command_info.get("target"),
                        "requires_confirmation": command_info.get("requires_confirmation", False),
                        "response_text": f"Executing: {command_info.get('description', intent)}"
                    }
        
        return {
            "success": True,
            "original_text": text,
            "intent": "unknown",
            "confidence": 0,
            "parameters": {},
            "response_text": "I didn't understand that command. Say 'help' to see available commands."
        }
    
    def _check_permission(self, intent, user_role):
        """
        Check if the user has permission to execute a command (internal use).
        """
        return self.check_permission(intent, user_role)
    
    def check_permission(self, intent, user_role):
        """
        Check if the user has permission to execute a command.
        
        Args:
            intent: The command intent
            user_role: User's role (admin, user, viewer)
            
        Returns:
            Boolean indicating if the user has permission
        """
        admin_only_commands = ["generate_report"]
        
        if intent in admin_only_commands and user_role not in ["admin"]:
            return False
        
        return True
    
    def get_help_text(self):
        """Get help text listing all available commands."""
        help_lines = ["Available voice commands:"]
        for cmd, info in self.SUPPORTED_COMMANDS.items():
            help_lines.append(f"- {info['description']}: say '{info['examples'][0]}'")
        
        return "\n".join(help_lines)
    
    def text_to_speech_data(self, text):
        """
        Generate text-to-speech audio data using OpenAI TTS.
        
        Args:
            text: Text to convert to speech
            
        Returns:
            Dictionary with base64 encoded audio data
        """
        if not self.openai:
            return {"error": "OpenAI API key not configured", "success": False, "use_browser_tts": True}
        
        try:
            response = self.openai.audio.speech.create(
                model="tts-1",
                voice="alloy",
                input=text
            )
            
            audio_data = base64.b64encode(response.content).decode('utf-8')
            
            return {
                "success": True,
                "audio_data": audio_data,
                "format": "mp3"
            }
            
        except Exception as e:
            logger.error(f"Error generating speech: {str(e)}")
            return {"error": str(e), "success": False, "use_browser_tts": True}


voice_processor = VoiceCommandProcessor()
