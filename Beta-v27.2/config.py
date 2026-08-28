import os


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

    @classmethod
    def get_wazuh_servers(cls):
        """Return the two Wazuh/OpenSearch server profiles.

        The first profile preserves the existing environment variable names.
        The second profile is opt-in through *_2 variables so an installation
        can add a standby/secondary manager without changing application code.
        """
        return {
            'primary': {
                'key': 'primary',
                'name': os.environ.get('WAZUH_SERVER_1_NAME', 'Primary Wazuh'),
                'wazuh_url': os.environ.get('WAZUH_API_URL', 'https://wazuh.rebiz.com:55000').rstrip('/'),
                'wazuh_user': os.environ.get('WAZUH_API_USER', 'wazuh-wui'),
                'wazuh_password': os.environ.get('WAZUH_API_PASSWORD',
                                                 'Jbbp1P*9ydI*EP7.Wa2MCLsKM?lcz+iH'),
                'wazuh_verify_ssl': os.environ.get('WAZUH_VERIFY_SSL', 'False') == 'True',
                'opensearch_url': os.environ.get('OPENSEARCH_URL', 'https://wazuh.rebiz.com:9200').rstrip('/'),
                'opensearch_user': os.environ.get('OPENSEARCH_USER', 'admin'),
                'opensearch_password': os.environ.get('OPENSEARCH_PASSWORD', 'W@zuh0pen1*'),
                'opensearch_verify_ssl': os.environ.get('OPENSEARCH_VERIFY_SSL', 'False') == 'True',
            },
            'secondary': {
                'key': 'secondary',
                'name': os.environ.get('WAZUH_SERVER_2_NAME', 'Secondary Wazuh'),
                'wazuh_url': os.environ.get('WAZUH_API_URL_2', '').rstrip('/'),
                'wazuh_user': os.environ.get('WAZUH_API_USER_2', ''),
                'wazuh_password': os.environ.get('WAZUH_API_PASSWORD_2', ''),
                'wazuh_verify_ssl': os.environ.get('WAZUH_VERIFY_SSL_2', 'False') == 'True',
                'opensearch_url': os.environ.get('OPENSEARCH_URL_2', '').rstrip('/'),
                'opensearch_user': os.environ.get('OPENSEARCH_USER_2', ''),
                'opensearch_password': os.environ.get('OPENSEARCH_PASSWORD_2', ''),
                'opensearch_verify_ssl': os.environ.get('OPENSEARCH_VERIFY_SSL_2', 'False') == 'True',
            },
        }

    @classmethod
    def get_server(cls, server_key='primary'):
        """Return a server profile, falling back to primary for bad keys."""
        return cls.get_wazuh_servers().get(server_key, cls.get_wazuh_servers()['primary'])

    @classmethod
    def get_server_options(cls):
        """Return safe-to-render server metadata; never expose credentials."""
        return [
            {
                'key': profile['key'],
                'name': profile['name'],
                'configured': bool(profile['wazuh_url'] and profile['wazuh_user'] and
                                    profile['wazuh_password'] and profile['opensearch_url'] and
                                    profile['opensearch_user'] and profile['opensearch_password']),
            }
            for profile in cls.get_wazuh_servers().values()
        ]
