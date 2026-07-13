from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import DeclarativeBase
import json
import os

class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the Base class
db = SQLAlchemy(model_class=Base)

# ---------------------------------------------------------------------------
# Module permission registry — the canonical list of all permission keys.
# Admins bypass all checks; non-admins must have each key explicitly granted.
# ---------------------------------------------------------------------------
MODULE_PERMISSIONS = {
    'dashboard':         'Dashboard',
    'alerts':            'Alerts',
    'ai_insights':       'AI Insights',
    'reports':           'Reports',
    'threat_intel':      'Threat Intelligence',
    'config_assessment': 'Config Assessment',
    'integrations':      'Integrations',
    'dvr_config':        'DVR/NVR AutoDeploy',
    'dvr_bulk':          'DVR/NVR Bulk AutoDeploy',
    'storage':           'Storage Management',
    'retention':         'Data Retention',
}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(50), default='agent')  # 'admin' or 'agent'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with other models
    alert_configs = db.relationship('AlertConfig', backref='user', lazy='dynamic')
    report_configs = db.relationship('ReportConfig', backref='user', lazy='dynamic')
    ai_templates = db.relationship('AiInsightTemplate', backref='user', lazy='dynamic')
    permissions = db.relationship('UserPermission', lazy='dynamic',
                                  cascade='all, delete-orphan',
                                  foreign_keys='UserPermission.user_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'

    # Default permissions granted automatically by role (no explicit DB grant needed).
    ROLE_DEFAULT_PERMISSIONS = {
        'dpcm': {'dvr_config', 'dvr_bulk'},
    }

    def has_permission(self, permission_key):
        """Return True if the user may access the given module.
        Administrators always return True; all others require an explicit grant
        OR a role-based default permission."""
        if self.is_admin():
            return True
        # Role-based defaults — no DB row required
        if permission_key in self.ROLE_DEFAULT_PERMISSIONS.get(self.role, set()):
            return True
        return db.session.query(UserPermission).filter_by(
            user_id=self.id, permission_key=permission_key).first() is not None

    def get_permissions(self):
        """Return the list of permission keys granted to this user.
        Admins receive every key in MODULE_PERMISSIONS."""
        if self.is_admin():
            return list(MODULE_PERMISSIONS.keys())
        return [p.permission_key for p in self.permissions]
    
    def __repr__(self):
        return f'<User {self.username}>'


class UserPermission(db.Model):
    """Per-module permission grant for a non-admin user."""
    __tablename__ = 'user_permission'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                        nullable=False)
    permission_key = db.Column(db.String(64), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'permission_key', name='uq_user_permission'),
    )

    def __repr__(self):
        return f'<UserPermission user={self.user_id} perm={self.permission_key}>'

class AlertConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    alert_levels = db.Column(db.String(100), nullable=False)  # JSON string of levels: ['critical', 'high', etc.]
    email_recipient = db.Column(db.String(1000), nullable=False)
    notify_time = db.Column(db.String(50))  # Time of day for notification
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    include_fields = db.Column(db.String(500))  # JSON string of fields to include in the alert

    # FIM-specific fields
    alert_type = db.Column(db.String(20), default='standard')  # 'standard' or 'fim'
    fim_agent_names = db.Column(db.Text)   # JSON list of agent names to monitor
    fim_paths = db.Column(db.Text)         # JSON list of syscheck paths to monitor
    fim_file_names = db.Column(db.Text)    # JSON list of optional file name filters
    fim_file_extensions = db.Column(db.Text)  # JSON list of optional file extension filters

    def get_alert_levels(self):
        if self.alert_levels:
            return json.loads(self.alert_levels)
        return []
    
    def set_alert_levels(self, levels):
        self.alert_levels = json.dumps(levels)
        
    def get_include_fields(self):
        if self.include_fields:
            return json.loads(self.include_fields)
        return ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"]
    
    def set_include_fields(self, fields):
        self.include_fields = json.dumps(fields)

    def get_fim_agent_names(self):
        if self.fim_agent_names:
            return json.loads(self.fim_agent_names)
        return []

    def set_fim_agent_names(self, names):
        self.fim_agent_names = json.dumps(names)

    def get_fim_paths(self):
        if self.fim_paths:
            return json.loads(self.fim_paths)
        return []

    def set_fim_paths(self, paths):
        self.fim_paths = json.dumps(paths)

    def get_fim_file_names(self):
        if self.fim_file_names:
            return json.loads(self.fim_file_names)
        return []

    def set_fim_file_names(self, names):
        self.fim_file_names = json.dumps(names)

    def get_fim_file_extensions(self):
        if self.fim_file_extensions:
            return json.loads(self.fim_file_extensions)
        return []

    def set_fim_file_extensions(self, exts):
        self.fim_file_extensions = json.dumps(exts)

    def is_fim(self):
        return self.alert_type == 'fim'

    def __repr__(self):
        return f'<AlertConfig {self.name}>'

class ReportConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    severity_levels = db.Column(db.String(100), nullable=False)  # JSON string
    format = db.Column(db.String(10), default='pdf')  # 'pdf' or 'html'
    schedule = db.Column(db.String(50))  # 'daily', 'weekly', etc.
    schedule_time = db.Column(db.String(50))  # Time of day
    recipients = db.Column(db.String(500))  # JSON string of email addresses
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_severity_levels(self):
        return json.loads(self.severity_levels)
    
    def set_severity_levels(self, levels):
        self.severity_levels = json.dumps(levels)
    
    def get_recipients(self):
        return json.loads(self.recipients)
    
    def set_recipients(self, recipients):
        self.recipients = json.dumps(recipients)
    
    def __repr__(self):
        return f'<ReportConfig {self.name}>'

class AiInsightTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    fields = db.Column(db.Text)  # JSON string of fields to analyze
    model_type = db.Column(db.String(50), default='openai')  # 'openai', 'deepseek', 'ollama'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_fields(self):
        return json.loads(self.fields)
    
    def set_fields(self, fields):
        self.fields = json.dumps(fields)
    
    def __repr__(self):
        return f'<AiInsightTemplate {self.name}>'

class AiInsightResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('ai_insight_template.id'), nullable=False)
    data_source = db.Column(db.Text)  # Source data used for analysis
    result = db.Column(db.Text)  # AI analysis result
    rating = db.Column(db.Float)  # User-provided rating
    follow_up_questions = db.Column(db.Text)  # JSON string of follow-up questions and answers
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    template = db.relationship('AiInsightTemplate', backref='results')
    
    def get_follow_up_questions(self):
        if self.follow_up_questions:
            return json.loads(self.follow_up_questions)
        return []
    
    def add_follow_up(self, question, answer):
        follow_ups = self.get_follow_up_questions()
        follow_ups.append({'question': question, 'answer': answer, 'timestamp': datetime.utcnow().isoformat()})
        self.follow_up_questions = json.dumps(follow_ups)
    
    def __repr__(self):
        return f'<AiInsightResult for template {self.template_id}>'


class RetentionPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Data Source
    source_type = db.Column(db.String(20), nullable=False)  # 'wazuh', 'opensearch', 'database'
    
    # Retention settings
    retention_days = db.Column(db.Integer, nullable=False)  # Number of days to retain data
    
    # Data filtering
    severity_levels = db.Column(db.String(100))  # JSON string ['critical', 'high', etc.]
    rule_ids = db.Column(db.Text)  # JSON string of rule IDs to include
    
    # Schedule
    cron_schedule = db.Column(db.String(100))  # Cron expression for scheduling
    last_run = db.Column(db.DateTime)  # Last execution timestamp
    
    # Status
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship back to user
    user = db.relationship('User', backref='retention_policies')
    
    def get_severity_levels(self):
        if self.severity_levels:
            return json.loads(self.severity_levels)
        return []
    
    def set_severity_levels(self, levels):
        self.severity_levels = json.dumps(levels)
    
    def get_rule_ids(self):
        if self.rule_ids:
            return json.loads(self.rule_ids)
        return []
    
    def set_rule_ids(self, rule_ids):
        self.rule_ids = json.dumps(rule_ids)
    
    def __repr__(self):
        return f'<RetentionPolicy {self.name} for {self.source_type}>'


class SentAlert(db.Model):
    """Track already sent alerts to prevent duplicates"""
    id = db.Column(db.Integer, primary_key=True)
    alert_config_id = db.Column(db.Integer, db.ForeignKey('alert_config.id'), nullable=False)
    alert_identifier = db.Column(db.String(500), nullable=False)  # Hash of unique alert identifiers
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define relationship to AlertConfig
    alert_config = db.relationship('AlertConfig', backref='sent_alerts')
    
    def __repr__(self):
        return f'<SentAlert {self.alert_identifier[:10]}... for config {self.alert_config_id}>'


class SystemConfig(db.Model):
    """
    Store global system configuration settings
    
    This model stores key-value pairs for system-wide configuration settings
    like refresh intervals, default values, and other app settings.
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_value(key, default=None):
        """Get a configuration value by key with an optional default"""
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            return config.value
        return default
    
    @staticmethod
    def set_value(key, value, description=None):
        """Set a configuration value, creating it if it doesn't exist"""
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            config.value = value
            config.updated_at = datetime.utcnow()
        else:
            config = SystemConfig(key=key, value=value, description=description)
            db.session.add(config)
        db.session.commit()
        return config
    
    def __repr__(self):
        return f'<SystemConfig {self.key}={self.value}>'


class StoredAlert(db.Model):
    """
    Store alerts from Wazuh/OpenSearch date-wise for AI search training.
    This allows the AI search engine to be trained on historical alert data.
    """
    id = db.Column(db.Integer, primary_key=True)
    alert_date = db.Column(db.Date, nullable=False, index=True)
    alert_timestamp = db.Column(db.DateTime, nullable=False, index=True)
    alert_id = db.Column(db.String(255), nullable=False)
    agent_id = db.Column(db.String(100))
    agent_name = db.Column(db.String(255))
    agent_ip = db.Column(db.String(50))
    rule_id = db.Column(db.String(100))
    rule_description = db.Column(db.Text)
    severity_level = db.Column(db.String(20))
    severity_numeric = db.Column(db.Integer)
    
    # Security-related fields
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    username = db.Column(db.String(255))
    event_type = db.Column(db.String(100))
    login_type = db.Column(db.String(50))
    rdp_activity = db.Column(db.String(255))
    file_path = db.Column(db.Text)  # Specific file or folder path (e.g., syscheck.path)
    
    # Raw alert data as JSON for full context
    raw_data = db.Column(db.Text)
    
    # Tracking
    stored_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    indexed_for_search = db.Column(db.Boolean, default=True, index=True)
    
    def to_dict(self):
        """Convert alert to dictionary for AI search"""
        return {
            'id': self.id,
            'alert_date': self.alert_date.isoformat() if self.alert_date else None,
            'alert_timestamp': self.alert_timestamp.isoformat() if self.alert_timestamp else None,
            'alert_id': self.alert_id,
            'agent': {
                'id': self.agent_id,
                'name': self.agent_name,
                'ip': self.agent_ip
            },
            'rule': {
                'id': self.rule_id,
                'description': self.rule_description
            },
            'severity': {
                'level': self.severity_level,
                'numeric': self.severity_numeric
            },
            'security_data': {
                'source_ip': self.source_ip,
                'destination_ip': self.destination_ip,
                'username': self.username,
                'event_type': self.event_type,
                'login_type': self.login_type,
                'rdp_activity': self.rdp_activity,
                'file_path': self.file_path
            }
        }
    
    def __repr__(self):
        return f'<StoredAlert {self.alert_id} on {self.alert_date}>'


class Conversation(db.Model):
    """
    Store AI Security Search conversations for session continuity.
    Each conversation contains multiple messages within a single session.
    Conversations are scoped to users to maintain privacy.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(255), nullable=False)  # Browser session ID
    messages = db.Column(db.Text)  # JSON array of messages
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='conversations')
    
    def get_messages(self):
        """Get conversation messages as list"""
        if self.messages:
            return json.loads(self.messages)
        return []
    
    def set_messages(self, messages):
        """Set conversation messages"""
        self.messages = json.dumps(messages)
    
    def add_message(self, role, content, provider_used=None):
        """Add a message to the conversation"""
        messages = self.get_messages()
        messages.append({
            'role': role,  # 'user' or 'assistant'
            'content': content,
            'provider_used': provider_used,
            'timestamp': datetime.utcnow().isoformat()
        })
        self.set_messages(messages)
    
    def __repr__(self):
        return f'<Conversation {self.id} for user {self.user_id}>'


class ThreatIntelItem(db.Model):
    """Stores threat intelligence items fetched from external feeds."""
    id = db.Column(db.Integer, primary_key=True)
    guid = db.Column(db.String(512), unique=True, nullable=False)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.Text)
    source = db.Column(db.String(100))
    published_at = db.Column(db.DateTime)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), default='unknown')
    has_patch = db.Column(db.Boolean, default=False)
    has_mitigation = db.Column(db.Boolean, default=False)
    relevance_score = db.Column(db.Integer, default=0)
    ai_analysis = db.Column(db.Text)
    ai_analyzed = db.Column(db.Boolean, default=False)
    email_sent = db.Column(db.Boolean, default=False)
    cve_ids = db.Column(db.Text)

    def get_cve_list(self):
        if self.cve_ids:
            return json.loads(self.cve_ids)
        return []

    def __repr__(self):
        return f'<ThreatIntelItem {self.title[:50]}>'


class ThreatIntelCorrelation(db.Model):
    """Stores the result of correlating a threat intel item against internal agent inventory."""
    id = db.Column(db.Integer, primary_key=True)
    threat_intel_item_id = db.Column(db.Integer, db.ForeignKey('threat_intel_item.id'), nullable=False, unique=True)
    correlated_at = db.Column(db.DateTime, default=datetime.utcnow)
    affected_agents = db.Column(db.Text)
    affected_count = db.Column(db.Integer, default=0)
    env_relevance_score = db.Column(db.Integer, default=0)
    env_recommended_action = db.Column(db.Text)
    correlation_summary = db.Column(db.Text)
    is_confirmed_present = db.Column(db.Boolean, default=False)
    potential_risk_agents = db.Column(db.Text)

    threat_item = db.relationship('ThreatIntelItem', backref=db.backref('correlation', uselist=False))

    def get_affected_agents(self):
        if self.affected_agents:
            return json.loads(self.affected_agents)
        return []

    def get_potential_risk_agents(self):
        if self.potential_risk_agents:
            return json.loads(self.potential_risk_agents)
        return []

    def __repr__(self):
        return f'<ThreatIntelCorrelation item={self.threat_intel_item_id} agents={self.affected_count}>'


class ThreatIntelConfig(db.Model):
    """Configuration for the Threat Intelligence monitor."""
    id = db.Column(db.Integer, primary_key=True)
    email_recipient = db.Column(db.String(200))
    enabled = db.Column(db.Boolean, default=True)
    notify_on_patch = db.Column(db.Boolean, default=True)
    notify_on_critical = db.Column(db.Boolean, default=True)
    min_relevance = db.Column(db.Integer, default=5)
    sources = db.Column(db.String(1000))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    ALL_SOURCES = ['cisa_kev', 'cisa_alerts', 'nvd', 'wazuh_cti', 'bleepingcomputer', 'hackernews', 'securityweek']

    def get_sources(self):
        if self.sources:
            stored = json.loads(self.sources)
            # Always include any new sources that have been added since this config was saved
            for s in self.ALL_SOURCES:
                if s not in stored:
                    stored.append(s)
            return stored
        return list(self.ALL_SOURCES)

    def set_sources(self, src_list):
        self.sources = json.dumps(src_list)

    @classmethod
    def get_instance(cls):
        cfg = cls.query.first()
        if not cfg:
            cfg = cls(email_recipient='', enabled=True, notify_on_patch=True, notify_on_critical=True, min_relevance=5)
            db.session.add(cfg)
            db.session.commit()
        return cfg

    def __repr__(self):
        return f'<ThreatIntelConfig email={self.email_recipient}>'


class DVRConfigSession(db.Model):
    """Stores a DVR/NVR auto-configuration wizard session."""
    id = db.Column(db.String(64), primary_key=True)
    data = db.Column(db.Text, nullable=False, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    bulk_job_id = db.Column(db.String(64), nullable=True)  # linked bulk job, if any

    def get_data(self):
        return json.loads(self.data) if self.data else {}

    def set_data(self, d):
        self.data = json.dumps(d)

    def __repr__(self):
        return f'<DVRConfigSession {self.id}>'


class DVRBulkJob(db.Model):
    """Tracks a bulk DVR/NVR auto-configuration job."""
    __tablename__ = 'dvr_bulk_jobs'
    id = db.Column(db.String(64), primary_key=True)
    created_by = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending|running|done|failed
    total = db.Column(db.Integer, default=0)
    completed = db.Column(db.Integer, default=0)
    succeeded = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    data_json = db.Column(db.Text, default='{}')

    def get_data(self):
        return json.loads(self.data_json or '{}')

    def set_data(self, d):
        self.data_json = json.dumps(d)

    def __repr__(self):
        return f'<DVRBulkJob {self.id} [{self.status}] {self.completed}/{self.total}>'


class SMBConfig(db.Model):
    """Singleton table storing the SMB network share configuration."""
    id = db.Column(db.Integer, primary_key=True)
    server_path = db.Column(db.String(300))     # e.g. \\server\share
    username    = db.Column(db.String(100))
    password    = db.Column(db.String(200))     # stored server-side; admin-only access
    domain      = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    last_tested = db.Column(db.DateTime)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def get_instance(cls):
        cfg = cls.query.first()
        if not cfg:
            cfg = cls()
            db.session.add(cfg)
            db.session.commit()
        return cfg

    def to_safe_dict(self):
        """Return config without exposing the raw password."""
        return {
            'server_path': self.server_path or '',
            'username':    self.username or '',
            'has_password': bool(self.password),
            'domain':      self.domain or '',
            'is_verified': self.is_verified,
            'last_tested': self.last_tested.strftime('%Y-%m-%d %H:%M') if self.last_tested else None,
        }

    def __repr__(self):
        return f'<SMBConfig {self.server_path}>'


class LogBackup(db.Model):
    """Tracks log backup archives exported from OpenSearch indices."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    log_type = db.Column(db.String(50))           # 'wazuh-alerts-*', 'wazuh-archives-*', 'all'
    months = db.Column(db.Text)                    # JSON list of 'YYYY.MM' strings
    indices = db.Column(db.Text)                   # JSON list of index names exported
    file_path = db.Column(db.String(500))          # local path or SMB UNC path to .ndjson.gz
    destination_type = db.Column(db.String(20), default='local')  # 'local' | 'smb'
    file_size_bytes = db.Column(db.BigInteger, default=0)
    doc_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')  # pending|running|complete|failed|restoring|restored
    error_message = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    def get_months(self):
        return json.loads(self.months) if self.months else []

    def get_indices(self):
        return json.loads(self.indices) if self.indices else []

    def file_exists(self):
        if not self.file_path:
            return False
        if self.destination_type == 'smb':
            return True   # SMB paths are not directly checkable via os.path
        return os.path.exists(self.file_path)

    def __repr__(self):
        return f'<LogBackup {self.name} [{self.status}]>'


class ExternalIntegration(db.Model):
    """
    Store configurations for external SIEM/SOAR integrations.
    Supports Webhooks for data exchange.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    integration_type = db.Column(db.String(50), default='webhook')  # 'webhook', 'splunk', 'sentinel'
    url = db.Column(db.String(500), nullable=False)
    api_key = db.Column(db.String(500))
    enabled = db.Column(db.Boolean, default=True)
    severity_threshold = db.Column(db.Integer, default=12) # Only send alerts >= this level
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='external_integrations')

    def __repr__(self):
        return f'<ExternalIntegration {self.name} ({self.integration_type})>'
