import logging
import time
from email_alerts import EmailAlerts
from app import app
from models import db, SystemConfig

logger = logging.getLogger('alert_worker')

def alert_worker():
    """
    Background worker that checks for new alerts and sends email notifications.
    """
    logger.info("Starting alert worker thread")
    email_manager = EmailAlerts()
    
    while True:
        try:
            with app.app_context():
                # Get check interval from system config (in minutes, default 2)
                interval_mins = int(SystemConfig.get_value('alert_check_interval', '2'))
                logger.debug(f"Alert worker checking for new alerts (interval: {interval_mins}m)")
                
                # Check and send alerts
                email_manager.check_and_send_alerts()
                
            # Wait for next check
            time.sleep(interval_mins * 60)
        except Exception as e:
            logger.error(f"Error in alert worker: {str(e)}")
            time.sleep(60) # Wait a minute before retrying on error

if __name__ == '__main__':
    alert_worker()
