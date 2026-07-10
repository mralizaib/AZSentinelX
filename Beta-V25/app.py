import os
import logging
from datetime import timedelta
from flask import Flask, g, redirect, url_for, session, request
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, current_user

# Configure more detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Set specific loggers to DEBUG level
for logger_name in ['scheduler', 'email_alerts', 'routes.admin', 'opensearch_api', 'report_generator']:
    logging.getLogger(logger_name).setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory circular log buffer — captures the most recent log lines so the
# Console Logs page can display them without reading disk files.
# ---------------------------------------------------------------------------
import collections
import threading

class _MemoryLogHandler(logging.Handler):
    """Thread-safe circular buffer that keeps the last MAX_LINES log records."""
    MAX_LINES = 800

    def __init__(self):
        super().__init__()
        self._buf = collections.deque(maxlen=self.MAX_LINES)
        self._lock = threading.Lock()
        self.setFormatter(logging.Formatter(
            '%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

    def emit(self, record):
        try:
            line = self.format(record)
            with self._lock:
                self._buf.append({
                    'ts': record.created,
                    'level': record.levelname,
                    'logger': record.name,
                    'msg': line,
                })
        except Exception:
            self.handleError(record)

    def get_lines(self, since_ts=0, limit=200):
        with self._lock:
            lines = [e for e in self._buf if e['ts'] > since_ts]
        return lines[-limit:]

# Install the handler on the root logger so it captures everything
_mem_handler = _MemoryLogHandler()
_mem_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(_mem_handler)

# Import db from models to avoid circular import
from models import db

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or "dev-fallback-key-change-in-production"
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database - Use Replit Database URL if available
database_url = os.environ.get("DATABASE_URL",'postgresql://postgres:DBp0stGs3cPa55722702@10.144.90.95:5432/wazuh')
if not database_url:
    # Fallback to SQLite for development
    # Use the current directory since we're already in InsightAnalyzer-Beta
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")
    database_url = f"sqlite:///{db_path}"
    logger.info(f"Using SQLite database for development at: {db_path}")
else:
    logger.info("Using PostgreSQL database from Replit")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "connect_args": {"connect_timeout": 10} if database_url and database_url.startswith("postgresql") else {},
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session cookie settings
# Non-permanent by default → browser-close destroys the session.
# Only set to permanent (with an expiry) when "Remember Me" is used.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Initialize the database
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"
login_manager.login_message_category = "danger"

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    from flask import request, jsonify, redirect, url_for
    # API requests must get a JSON 401 — never an HTML redirect
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
    return redirect(url_for('auth.login', next=request.url))

# Import and register blueprints after db initialization
try:
    # Import and register blueprints
    try:
        from routes.auth import auth_bp
        app.register_blueprint(auth_bp)
    except ImportError as e:
        logger.warning(f"Could not import auth blueprint: {e}")

    try:
        from routes.dashboard import dashboard_bp
        app.register_blueprint(dashboard_bp)
    except ImportError as e:
        logger.warning(f"Could not import dashboard blueprint: {e}")

    try:
        from routes.admin import admin_bp
        app.register_blueprint(admin_bp, url_prefix='/admin')
    except ImportError as e:
        logger.warning(f"Could not import admin blueprint: {e}")

    try:
        from routes.alerts import alerts_bp
        app.register_blueprint(alerts_bp)
    except ImportError as e:
        logger.warning(f"Could not import alerts blueprint: {e}")

    try:
        from routes.config import config_bp
        app.register_blueprint(config_bp)
    except ImportError as e:
        logger.warning(f"Could not import config blueprint: {e}")

    try:
        from routes.insights import insights_bp
        app.register_blueprint(insights_bp)
    except ImportError as e:
        logger.warning(f"Could not import insights blueprint: {e}")

    try:
        from routes.users import users_bp
        app.register_blueprint(users_bp)
    except ImportError as e:
        logger.warning(f"Could not import users blueprint: {e}")

    try:
        from routes.retention import retention_bp
        app.register_blueprint(retention_bp)
    except ImportError as e:
        logger.warning(f"Could not import retention blueprint: {e}")

    # Try to import reports blueprint separately
    try:
        from routes.reports import reports_bp
        app.register_blueprint(reports_bp)
        logger.info("Reports blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import reports blueprint: {e}")

    # Try to import voice blueprint separately
    try:
        from routes.voice import voice_bp
        app.register_blueprint(voice_bp)
        logger.info("Voice command blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import voice blueprint: {e}")

    try:
        from routes.integrations import integrations_bp
        app.register_blueprint(integrations_bp)
        logger.info("Integrations blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import integrations blueprint: {e}")

    try:
        from routes.storage import storage_bp
        app.register_blueprint(storage_bp)
        logger.info("Storage management blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import storage blueprint: {e}")

    try:
        from routes.threat_intel import threat_intel_bp
        app.register_blueprint(threat_intel_bp)
        logger.info("Threat Intelligence blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import threat_intel blueprint: {e}")

    try:
        from routes.config_assessment import config_assessment_bp
        app.register_blueprint(config_assessment_bp)
        logger.info("Configuration Assessment blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import config_assessment blueprint: {e}")

    try:
        from routes.dvr_config import dvr_config_bp
        app.register_blueprint(dvr_config_bp)
        logger.info("DVR/NVR Auto-Configuration blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import dvr_config blueprint: {e}")

    try:
        from routes.dvr_bulk import dvr_bulk_bp
        app.register_blueprint(dvr_bulk_bp)
        logger.info("DVR/NVR Bulk Configuration blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import dvr_bulk blueprint: {e}")

    try:
        from routes.permissions import permissions_bp
        app.register_blueprint(permissions_bp)
        logger.info("Permissions blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import permissions blueprint: {e}")

    logger.info("Blueprints registered successfully")
except ImportError as e:
    logger.warning(f"Could not import some blueprints: {e}")
    # Continue without the problematic blueprint

# Initialize the scheduler for background tasks
try:
    import scheduler
    scheduler.init_app(app)
    logger.info("Scheduler initialized successfully")
except Exception as e:
    logger.warning(f"Scheduler initialization issue: {e}")
    # Scheduler may already be running, continue anyway

# Create tables and default admin user within app context
with app.app_context():
    try:
        from models import (User, AlertConfig, ReportConfig, AiInsightTemplate, AiInsightResult,
                            RetentionPolicy, SentAlert, SystemConfig, StoredAlert,
                            ThreatIntelItem, ThreatIntelConfig, ThreatIntelCorrelation,
                            LogBackup, SMBConfig, DVRConfigSession, DVRBulkJob)
        db.create_all()

        # Add new columns to existing tables that may predate them.
        # Using IF NOT EXISTS so this is safe to run on every startup.
        try:
            db.session.execute(db.text(
                "ALTER TABLE threat_intel_correlation "
                "ADD COLUMN IF NOT EXISTS potential_risk_agents TEXT"
            ))
            db.session.commit()
        except Exception as _col_err:
            db.session.rollback()
            logger.debug(f"Column migration note: {_col_err}")

        # FIM alert config columns migration
        for _fim_col, _fim_type in [
            ("alert_type", "VARCHAR(20) DEFAULT 'standard'"),
            ("fim_agent_names", "TEXT"),
            ("fim_paths", "TEXT"),
            ("fim_file_names", "TEXT"),
            ("fim_file_extensions", "TEXT"),
        ]:
            try:
                db.session.execute(db.text(
                    f"ALTER TABLE alert_config ADD COLUMN IF NOT EXISTS {_fim_col} {_fim_type}"
                ))
                db.session.commit()
            except Exception as _fim_err:
                db.session.rollback()
                logger.debug(f"FIM column migration note ({_fim_col}): {_fim_err}")

        # LogBackup: add destination_type column for SMB support
        try:
            db.session.execute(db.text(
                "ALTER TABLE log_backup ADD COLUMN IF NOT EXISTS destination_type VARCHAR(20) DEFAULT 'local'"
            ))
            db.session.commit()
        except Exception as _lb_err:
            db.session.rollback()
            logger.debug(f"LogBackup migration note: {_lb_err}")

        # Create default admin user if no users exist
        if User.query.count() == 0:
            default_admin = User(
                username="admin",
                email="admin@example.com",
                role="admin"
            )
            default_admin.set_password("admin123")
            db.session.add(default_admin)
            db.session.commit()
            logger.info("Created default admin user")
        
        # Ensure default AI provider is set to gemini if requested
        from models import SystemConfig
        if not SystemConfig.get_value('default_ai_provider'):
            SystemConfig.set_value('default_ai_provider', 'gemini')
            logger.info("Set default AI provider to gemini")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Trigger an initial threat intel refresh on startup if the DB is empty
try:
    import threading
    def _startup_threat_intel_refresh():
        import time
        time.sleep(10)  # small delay to let the scheduler and DB settle
        try:
            from threat_intel_service import run_full_refresh
            with app.app_context():
                from models import ThreatIntelItem
                count = ThreatIntelItem.query.count()
            if count == 0:
                logger.info("No threat intel items found — running initial feed refresh on startup")
                run_full_refresh(app)
            else:
                logger.info(f"Threat intel already has {count} items — skipping startup refresh")
        except Exception as e:
            logger.error(f"Startup threat intel refresh failed: {e}", exc_info=True)
    threading.Thread(target=_startup_threat_intel_refresh, daemon=True).start()
except Exception as e:
    logger.warning(f"Could not start threat intel startup refresh thread: {e}")

@app.before_request
def before_request():
    g.user = current_user
    if current_user.is_authenticated:
        # Touch the session so idle-timeout works correctly.
        # session.permanent is set at login time based on "Remember Me".
        session.modified = True

@app.route('/')
def index():
    return redirect(url_for('dashboard.index'))

@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='css/byteit-logo.jpg'))

# Error handlers
@app.errorhandler(404)
def page_not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    try:
        db.session.rollback()
    except:
        pass
    logger.error(f"Internal server error: {error}")
    return "Internal server error", 500

# Start alert worker thread — guard against Werkzeug debug-mode double-spawn.
# In debug mode the reloader launches two processes; WERKZEUG_RUN_MAIN is set
# to 'true' only in the actual server child, so we start the worker there only.
import os as _os
if _os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
    try:
        import threading
        from alert_worker import alert_worker
        worker_thread = threading.Thread(target=alert_worker, daemon=True)
        worker_thread.start()
        logger.info("Alert worker thread started successfully")
    except Exception as e:
        logger.error(f"Failed to start alert worker thread: {e}")
else:
    logger.debug("Skipping alert worker start in Werkzeug reloader watcher process")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting Flask app on port {port}")
    app.run(debug=True, host='0.0.0.0', port=port)