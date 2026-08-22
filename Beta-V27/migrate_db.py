
#!/usr/bin/env python3
"""
Database migration script to add missing columns to existing tables
"""
import sqlite3
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """Add missing columns to the database"""
    db_path = os.path.join('instance', 'sentinel.db')
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if include_fields column exists in alert_config table
        cursor.execute("PRAGMA table_info(alert_config)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'include_fields' not in columns:
            logger.info("Adding include_fields column to alert_config table")
            cursor.execute("ALTER TABLE alert_config ADD COLUMN include_fields VARCHAR(500)")
            conn.commit()
            logger.info("Successfully added include_fields column")
        else:
            logger.info("include_fields column already exists")
        
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error migrating database: {e}")
        return False

if __name__ == "__main__":
    migrate_database()
