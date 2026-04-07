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

# Import db from models to avoid circular import
from models import db

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or "dev-fallback-key-change-in-production"
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database - Use Replit Database URL if available
database_url = os.environ.get("DATABASE_URL")
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

# Set the permanent session lifetime
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

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
        from routes.itdr import itdr_bp
        app.register_blueprint(itdr_bp)
        logger.info("ITDR/XDR blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import ITDR blueprint: {e}")

    try:
        from routes.noise_filters import noise_filters_bp
        app.register_blueprint(noise_filters_bp)
        logger.info("Noise Filters blueprint registered successfully")
    except ImportError as e:
        logger.warning(f"Could not import noise_filters blueprint: {e}")

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
                            NoiseFilter, ActiveThreatNotification)
        db.create_all()

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

        # Seed default noise suppression filters (idempotent)
        try:
            from log_filter_engine import seed_default_filters
            seed_default_filters(app)
        except Exception as seed_exc:
            logger.warning(f"Noise filter seeding skipped: {seed_exc}")

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
    # Check if user is authenticated and accessing a non-auth route
    if current_user.is_authenticated:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)
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

# Start alert worker thread
try:
    import threading
    from alert_worker import alert_worker
    worker_thread = threading.Thread(target=alert_worker, daemon=True)
    worker_thread.start()
    logger.info("Alert worker thread started successfully")
except Exception as e:
    logger.error(f"Failed to start alert worker thread: {e}")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting Flask app on port {port}")
    app.run(debug=True, host='0.0.0.0', port=port)