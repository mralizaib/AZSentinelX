import os
import json


class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-secret-key')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True') == 'True'

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Wazuh API configuration
    WAZUH_API_URL = os.environ.get('WAZUH_API_URL',
                                   'https://wazuh.rebiz.com:55000')
    WAZUH_API_USER = os.environ.get('WAZUH_API_USER', 'wazuh-wui')
    WAZUH_API_PASSWORD = os.environ.get('WAZUH_API_PASSWORD',
                                        'Jbbp1P*9ydI*EP7.Wa2MCLsKM?lcz+iH')
    WAZUH_VERIFY_SSL = os.environ.get('WAZUH_VERIFY_SSL', 'False') == 'True'

    @classmethod
    def wazuh_centers(cls):
        """Return configured monitoring centers without exposing credentials."""
        centers = {
            'current': {
                'name': os.environ.get('WAZUH_CURRENT_CENTER_NAME', 'PK Center'),
                'wazuh_api_url': cls.WAZUH_API_URL,
                'opensearch_url': cls.OPENSEARCH_URL,
                'wazuh_user': cls.WAZUH_API_USER,
                'wazuh_password': cls.WAZUH_API_PASSWORD,
                'opensearch_user': cls.OPENSEARCH_USER,
                'opensearch_password': cls.OPENSEARCH_PASSWORD,
                'verify_ssl': cls.WAZUH_VERIFY_SSL,
            },
        }
        usa_api = os.environ.get('WAZUH_USA_API_URL', '').strip()
        if usa_api:
            centers['usa'] = {
                'name': os.environ.get('WAZUH_USA_CENTER_NAME', 'USA Center'),
                'wazuh_api_url': usa_api,
                'opensearch_url': os.environ.get('OPENSEARCH_USA_URL', ''),
                'wazuh_user': os.environ.get('WAZUH_USA_API_USER', cls.WAZUH_API_USER),
                'wazuh_password': os.environ.get('WAZUH_USA_API_PASSWORD', ''),
                'opensearch_user': os.environ.get('OPENSEARCH_USA_USER', cls.OPENSEARCH_USER),
                'opensearch_password': os.environ.get('OPENSEARCH_USA_PASSWORD', ''),
                'verify_ssl': os.environ.get('WAZUH_USA_VERIFY_SSL', 'False') == 'True',
            }
        try:
            extra = json.loads(os.environ.get('WAZUH_CENTERS_JSON', '{}'))
            for key, value in extra.items():
                if isinstance(value, dict) and value.get('wazuh_api_url'):
                    centers[key] = {
                        'name': value.get('name', key),
                        'wazuh_api_url': value['wazuh_api_url'],
                        'opensearch_url': value.get('opensearch_url', ''),
                        'wazuh_user': value.get('wazuh_user', cls.WAZUH_API_USER),
                        'wazuh_password': value.get('wazuh_password', ''),
                        'opensearch_user': value.get('opensearch_user', cls.OPENSEARCH_USER),
                        'opensearch_password': value.get('opensearch_password', ''),
                        'verify_ssl': bool(value.get('verify_ssl', cls.WAZUH_VERIFY_SSL)),
                    }
        except (TypeError, ValueError):
            pass
        return centers

    # OpenSearch configuration
    OPENSEARCH_URL = os.environ.get('OPENSEARCH_URL',
                                    'https://wazuh.rebiz.com:9200')
    OPENSEARCH_USER = os.environ.get('OPENSEARCH_USER', 'admin')
    OPENSEARCH_PASSWORD = os.environ.get('OPENSEARCH_PASSWORD', 'W@zuh0pen1*')
    OPENSEARCH_VERIFY_SSL = os.environ.get('OPENSEARCH_VERIFY_SSL',
                                           'False') == 'True'
    OPENSEARCH_INDEX_PATTERN = os.environ.get('OPENSEARCH_INDEX_PATTERN',
                                              'wazuh-alerts-*')

    # AI Model configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY','')
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY', '')
    OLLAMA_API_URL = os.environ.get('OLLAMA_API_URL', 'http://localhost:11434')
    
    # Gemini AI Integration (Replit AI Integrations)
    GEMINI_API_KEY = os.environ.get('AI_INTEGRATIONS_GEMINI_API_KEY', '')
    GEMINI_BASE_URL = os.environ.get('AI_INTEGRATIONS_GEMINI_BASE_URL', 'https://generativelanguage.googleapis.com/v1beta')

    # Email configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'wazuhtestalert@gmail.com')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'hiqvewuibpbhyqwg')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True') == 'True'
    SMTP_SENDER_NAME = os.environ.get('SMTP_SENDER_NAME', 'WAZUH Alerts')
    # Alert severity levels mapping
    SEVERITY_LEVELS = {
        'critical': 15,  # Level 15
        'high': list(range(12, 15)),  # Levels 12-14
        'medium': list(range(7, 12)),  # Levels 7-11
        'low': list(range(1, 7)),  # Levels 1-6
        'fim': [553, 554]  # FIM Rule IDs
    }
