import os
import json
import logging
import requests
from config import Config

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
from openai import OpenAI

# Gemini integration using Replit AI Integrations (requires google-genai package)
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

logger = logging.getLogger(__name__)

class AIInsights:
    def __init__(self, model_type=None):
        """
        Initialize AIInsights with intelligent provider fallback.
        
        Args:
            model_type: The primary AI provider to use. If None, uses system default.
                       Supported: 'openai', 'gemini', 'deepseek', 'ollama'
        """
        # Get the configured default AI provider from SystemConfig if model_type not specified
        if model_type is None:
            from models import SystemConfig
            default_provider = SystemConfig.get_value('default_ai_provider', 'openai')
            self.model_type = default_provider
            self.original_model_type = default_provider
        else:
            self.model_type = model_type
            self.original_model_type = model_type
        
        # Initialize model-specific clients
        self.openai = None
        self.gemini_client = None
        
        # Try to initialize the primary provider
        if self.model_type == "openai" and Config.OPENAI_API_KEY:
            self.openai = OpenAI(api_key=Config.OPENAI_API_KEY)
        elif self.model_type == "gemini" and Config.GEMINI_API_KEY and Config.GEMINI_BASE_URL and GEMINI_AVAILABLE:
            try:
                self.gemini_client = genai.Client(
                    api_key=Config.GEMINI_API_KEY,
                    http_options={
                        'api_version': '',
                        'base_url': Config.GEMINI_BASE_URL
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")
                self.gemini_client = None
    
    def ask_wazuh_question(self, question, context_data=None, language=None):
        """
        Answer a question about Wazuh, security alerts, or the system.
        Supports multi-language responses - responds in the same language as the question.
        
        Args:
            question: The user's question (in any language)
            context_data: Optional alert data or context to include
            language: Optional language hint (auto-detected if not provided)
            
        Returns:
            Dictionary with the answer and summary
        """
        # Build system prompt based on whether we have context data
        if context_data:
            system_prompt = """You are an expert cybersecurity analyst specializing in Wazuh SIEM (Security Information and Event Management) and security alert analysis.

CRITICAL INSTRUCTIONS:
1. You have been provided with ACTUAL SECURITY ALERT DATA from the system
2. ANALYZE AND INTERPRET THIS DATA FIRST - do NOT provide generic advice
3. Base your answer DIRECTLY on the alert data provided
4. Extract specific details: usernames, IP addresses, timestamps, agents, rules, severity levels
5. Provide CONCRETE FINDINGS from the data, not theoretical guidance

Your response must include:
- A professional, structured summary of the findings
- Direct answers based on the actual alert data, focusing on "Who did what and where"
- Specific details from alerts: User Name, Computer Name/Agent, and IP Activity
- For failed login attempts (Event ID 4625), prioritize identifying the source IP and targeted username
- Pattern analysis if multiple alerts exist (e.g., brute force attempts or rapid file modifications)
- Risk assessment based on actual events
- Actionable recommendations in a clear, bulleted format
- NO generic "you need to query" advice when data is already provided

Format the response using Markdown with bold headers and lists for maximum readability. Avoid technical jargon where possible, explaining security terms in plain language.

IMPORTANT LANGUAGE RULE: You MUST respond in the EXACT SAME LANGUAGE as the user's question.
Supported languages include:
- English
- Spanish (Español)
- French (Français)
- German (Deutsch)
- Chinese (中文)
- Japanese (日本語)
- Arabic (العربية)
- Hindi (हिंदी)
- Punjabi (ਪੰਜਾਬੀ)
- Urdu (اردو)
- Russian (Русский)
- Portuguese (Português)
- And any other language the user uses

If the question is in Hindi, respond entirely in Hindi. If in Punjabi, respond in Punjabi. If in Urdu, respond in Urdu. Match their language exactly.

Be precise, factual, and focused on the actual alert data provided."""
        else:
            system_prompt = """You are an expert cybersecurity assistant specializing in Wazuh SIEM (Security Information and Event Management), OpenSearch, and security alert analysis.

Your capabilities include:
- Explaining Wazuh concepts, rules, decoders, and configurations
- Analyzing security alerts and identifying threats
- Providing recommendations for security improvements
- Helping with incident response and threat hunting
- Explaining MITRE ATT&CK techniques and tactics

IMPORTANT LANGUAGE RULE: You MUST respond in the EXACT SAME LANGUAGE as the user's question.
Supported languages include:
- English
- Spanish (Español)
- French (Français)
- German (Deutsch)
- Chinese (中文)
- Japanese (日本語)
- Arabic (العربية)
- Hindi (हिंदी)
- Punjabi (ਪੰਜਾਬੀ)
- Urdu (اردو)
- Russian (Русский)
- Portuguese (Português)
- And any other language the user uses

If the question is in Hindi, respond entirely in Hindi. If in Punjabi, respond in Punjabi. If in Urdu, respond in Urdu. Match their language exactly.

When analyzing data, provide:
1. A clear, concise answer to the question in the user's language
2. Relevant context and explanation
3. Actionable recommendations when applicable

Be helpful, accurate, and security-focused in your responses."""

        user_content = question
        if context_data:
            if isinstance(context_data, (list, dict)):
                context_str = json.dumps(context_data, indent=2)
            else:
                context_str = str(context_data)
            user_content = f"SECURITY ALERT DATA FROM SYSTEM:\n{context_str}\n\n---\n\nANALYZE THE ABOVE DATA AND ANSWER THIS QUESTION:\n{question}"
        else:
            user_content = f"Question: {question}"
        
        # Try primary provider first, then fallback to available alternatives
        if self.model_type == "openai":
            result = self._ask_with_openai(system_prompt, user_content)
        elif self.model_type == "gemini":
            result = self._ask_with_gemini(system_prompt, user_content)
        elif self.model_type == "deepseek":
            result = self._ask_with_deepseek(system_prompt, user_content)
        elif self.model_type == "ollama":
            result = self._ask_with_ollama(system_prompt, user_content)
        else:
            result = {"error": f"Unsupported AI model type: {self.model_type}"}
        
        # If primary provider failed, try fallback providers
        if "error" in result and self.model_type != "openai":
            logger.warning(f"Primary provider ({self.model_type}) failed, attempting fallback to OpenAI")
            result = self._ask_with_openai(system_prompt, user_content)
            if "error" not in result:
                result["provider_used"] = "openai (fallback)"
                return result
        
        if "error" in result and self.model_type != "gemini":
            logger.warning(f"Providers failed, attempting fallback to Gemini")
            result = self._ask_with_gemini(system_prompt, user_content)
            if "error" not in result:
                result["provider_used"] = "gemini (fallback)"
                return result
        
        return result
    
    def _ask_with_gemini(self, system_prompt, user_content):
        """Ask a question using Gemini via Replit AI Integrations"""
        if not GEMINI_AVAILABLE:
            return {"error": "Gemini library not available (google-genai not installed)"}
        
        if not Config.GEMINI_API_KEY or not Config.GEMINI_BASE_URL:
            return {"error": "Gemini API configuration not available"}
        
        try:
            if not self.gemini_client:
                self.gemini_client = genai.Client(
                    api_key=Config.GEMINI_API_KEY,
                    http_options={
                        'api_version': '',
                        'base_url': Config.GEMINI_BASE_URL
                    }
                )
            
            response = self.gemini_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=[
                    {"role": "user", "parts": [{"text": f"System: {system_prompt}\n\nUser: {user_content}"}]}
                ]
            )
            
            answer = response.text if hasattr(response, 'text') else str(response)
            
            # Generate summary
            summary_response = self.gemini_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=[
                    {"role": "user", "parts": [{"text": f"Create a brief 1-2 sentence summary of this answer. Use the same language as the original answer.\n\n{answer}"}]}
                ]
            )
            
            summary = summary_response.text if hasattr(summary_response, 'text') else str(summary_response)
            
            return {
                "success": True,
                "answer": answer,
                "summary": summary,
                "model": "gemini-2.5-flash",
                "provider": "gemini"
            }
        except Exception as e:
            logger.error(f"Error with Gemini Q&A: {str(e)}")
            return {"error": str(e)}
    
    def _ask_with_openai(self, system_prompt, user_content):
        """Ask a question using OpenAI"""
        if not self.openai:
            if not Config.OPENAI_API_KEY:
                return {"error": "OpenAI API key not configured"}
            self.openai = OpenAI(api_key=Config.OPENAI_API_KEY)
        
        try:
            response = self.openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=2000,
                temperature=0.3 # Lower temperature for more factual results
            )
            
            answer = response.choices[0].message.content
            
            summary_response = self.openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "Create a professional 1-2 sentence summary of this security analysis. Focus on the core risk and primary actors involved. Use the same language as the original answer."},
                    {"role": "user", "content": answer}
                ],
                max_tokens=150
            )
            
            summary = summary_response.choices[0].message.content
            
            return {
                "success": True,
                "answer": answer,
                "summary": summary,
                "model": "gpt-4o",
                "provider": "openai"
            }
        except Exception as e:
            logger.error(f"Error with OpenAI Q&A: {str(e)}")
            return {"error": str(e)}
    
    def _ask_with_deepseek(self, system_prompt, user_content):
        """Ask a question using DeepSeek"""
        if not Config.DEEPSEEK_API_KEY:
            return {"error": "DeepSeek API key not configured"}
        
        try:
            headers = {
                "Authorization": f"Bearer {Config.DEEPSEEK_API_KEY}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                "max_tokens": 2000
            }
            
            response = requests.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                answer = result["choices"][0]["message"]["content"]
                
                summary_data = {
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": "Create a brief 1-2 sentence summary of this answer. Use the same language as the original answer."},
                        {"role": "user", "content": answer}
                    ],
                    "max_tokens": 150
                }
                
                summary_response = requests.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    headers=headers,
                    json=summary_data
                )
                
                summary = ""
                if summary_response.status_code == 200:
                    summary = summary_response.json()["choices"][0]["message"]["content"]
                
                return {
                    "success": True,
                    "answer": answer,
                    "summary": summary,
                    "model": "deepseek-chat",
                    "provider": "deepseek"
                }
            else:
                logger.error(f"DeepSeek API error: {response.text}")
                return {"error": f"DeepSeek API error: {response.text}"}
        except Exception as e:
            logger.error(f"Error with DeepSeek Q&A: {str(e)}")
            return {"error": str(e)}
    
    def _ask_with_ollama(self, system_prompt, user_content):
        """Ask a question using Ollama local LLM"""
        ollama_url = Config.OLLAMA_API_URL
        
        try:
            data = {
                "model": "llama3",
                "prompt": f"{system_prompt}\n\nUser: {user_content}",
                "stream": False
            }
            
            response = requests.post(
                f"{ollama_url}/api/generate",
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                answer = result["response"]
                
                summary_data = {
                    "model": "llama3",
                    "prompt": f"Create a brief 1-2 sentence summary of this answer. Use the same language as the original answer:\n\n{answer}",
                    "stream": False
                }
                
                summary_response = requests.post(
                    f"{ollama_url}/api/generate",
                    json=summary_data
                )
                
                summary = ""
                if summary_response.status_code == 200:
                    summary = summary_response.json()["response"]
                
                return {
                    "success": True,
                    "answer": answer,
                    "summary": summary,
                    "model": "llama3",
                    "provider": "ollama"
                }
            else:
                logger.error(f"Ollama API error: {response.text}")
                return {"error": f"Ollama API error: {response.text}"}
        except Exception as e:
            logger.error(f"Error with Ollama Q&A: {str(e)}")
            return {"error": str(e)}
        
    def analyze_alerts(self, alerts_data, analysis_prompt=None, fields=None):
        """
        Analyze security alerts using the specified AI model
        
        Args:
            alerts_data: List of alert data or text to analyze
            analysis_prompt: Custom prompt for the analysis
            fields: Specific fields to include in the analysis
            
        Returns:
            Dictionary with analysis results
        """
        if not analysis_prompt:
            analysis_prompt = "Analyze these security alerts for patterns, potential threats, and recommended actions:"
        
        # Extract specified fields if needed
        if fields and isinstance(alerts_data, list):
            filtered_data = []
            for alert in alerts_data:
                filtered_alert = {}
                for field in fields:
                    if field in alert:
                        filtered_alert[field] = alert[field]
                filtered_data.append(filtered_alert)
            alerts_data = filtered_data
        
        # Convert to string if it's not already
        if isinstance(alerts_data, (list, dict)):
            content = json.dumps(alerts_data, indent=2)
        else:
            content = str(alerts_data)
        
        # Combine prompt and data
        full_prompt = f"{analysis_prompt}\n\n{content}"
        
        # Try primary provider first, then fallback to available alternatives
        if self.model_type == "openai":
            result = self._analyze_with_openai(full_prompt)
        elif self.model_type == "gemini":
            result = self._analyze_with_gemini(full_prompt)
        elif self.model_type == "deepseek":
            result = self._analyze_with_deepseek(full_prompt)
        elif self.model_type == "ollama":
            result = self._analyze_with_ollama(full_prompt)
        else:
            result = {"error": f"Unsupported AI model type: {self.model_type}"}
        
        # Fallback logic for analysis
        if "error" in result and self.model_type != "openai":
            logger.warning(f"Primary provider ({self.model_type}) failed in analysis, attempting fallback to OpenAI")
            result = self._analyze_with_openai(full_prompt)
            if "error" not in result:
                result["provider_used"] = "openai (fallback)"
                return result
        
        if "error" in result and self.model_type != "gemini":
            logger.warning(f"Analysis providers failed, attempting fallback to Gemini")
            result = self._analyze_with_gemini(full_prompt)
            if "error" not in result:
                result["provider_used"] = "gemini (fallback)"
                return result
        
        return result
    
    def _analyze_with_gemini(self, prompt):
        """Analyze using Gemini models via Replit AI Integrations"""
        if not GEMINI_AVAILABLE:
            return {"error": "Gemini library not available"}
        
        if not Config.GEMINI_API_KEY or not Config.GEMINI_BASE_URL:
            return {"error": "Gemini API configuration not available"}
        
        try:
            if not self.gemini_client:
                self.gemini_client = genai.Client(
                    api_key=Config.GEMINI_API_KEY,
                    http_options={
                        'api_version': '',
                        'base_url': Config.GEMINI_BASE_URL
                    }
                )
            
            response = self.gemini_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=[
                    {"role": "user", "parts": [{"text": f"You are a cybersecurity expert analyzing security alerts from Wazuh. Provide insightful analysis, identify patterns or suspicious activities, and suggest actionable recommendations.\n\n{prompt}"}]}
                ]
            )
            
            analysis = response.text if hasattr(response, 'text') else str(response)
            
            return {
                "analysis": analysis,
                "model": "gemini-2.5-flash",
                "provider": "gemini"
            }
        except Exception as e:
            logger.error(f"Error with Gemini analysis: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_with_openai(self, prompt):
        """Analyze using OpenAI models"""
        if not self.openai:
            if not Config.OPENAI_API_KEY:
                return {"error": "OpenAI API key not configured"}
            self.openai = OpenAI(api_key=Config.OPENAI_API_KEY)
        
        try:
            response = self.openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing security alerts from Wazuh. Provide insightful analysis, identify patterns or suspicious activities, and suggest actionable recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500
            )
            
            return {
                "analysis": response.choices[0].message.content,
                "model": "gpt-4o",
                "provider": "openai"
            }
        except Exception as e:
            logger.error(f"Error with OpenAI analysis: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_with_deepseek(self, prompt):
        """Analyze using DeepSeek models"""
        if not Config.DEEPSEEK_API_KEY:
            return {"error": "DeepSeek API key not configured"}
        
        try:
            headers = {
                "Authorization": f"Bearer {Config.DEEPSEEK_API_KEY}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert analyzing security alerts from Wazuh. Provide insightful analysis, identify patterns or suspicious activities, and suggest actionable recommendations."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 1500
            }
            
            response = requests.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result["choices"][0]["message"]["content"],
                    "model": "deepseek-chat",
                    "provider": "deepseek"
                }
            else:
                logger.error(f"DeepSeek API error: {response.text}")
                return {"error": f"DeepSeek API error: {response.text}"}
        except Exception as e:
            logger.error(f"Error with DeepSeek analysis: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_with_ollama(self, prompt):
        """Analyze using Ollama local LLM"""
        ollama_url = Config.OLLAMA_API_URL
        
        try:
            data = {
                "model": "llama3",  # Default model, change as needed
                "prompt": prompt,
                "stream": False
            }
            
            response = requests.post(
                f"{ollama_url}/api/generate",
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result["response"],
                    "model": "llama3",
                    "provider": "ollama"
                }
            else:
                logger.error(f"Ollama API error: {response.text}")
                return {"error": f"Ollama API error: {response.text}"}
        except Exception as e:
            logger.error(f"Error with Ollama analysis: {str(e)}")
            return {"error": str(e)}
    
    def follow_up_question(self, previous_context, question, model_type=None):
        """
        Ask a follow-up question based on previous analysis
        
        Args:
            previous_context: Previous analysis or conversation
            question: Follow-up question
            model_type: Override the model type (optional)
            
        Returns:
            Dictionary with follow-up analysis
        """
        model = model_type or self.model_type
        
        prompt = f"""Previous analysis:
{previous_context}

Follow-up question:
{question}

Please provide a detailed answer to the follow-up question based on the previous analysis:"""
        
        if model == "openai":
            return self._analyze_with_openai(prompt)
        elif model == "deepseek":
            return self._analyze_with_deepseek(prompt)
        elif model == "ollama":
            return self._analyze_with_ollama(prompt)
        else:
            return {"error": f"Unsupported AI model type: {model}"}
