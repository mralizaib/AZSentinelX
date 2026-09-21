#!/bin/bash
set -e

# Create necessary directories
mkdir -p logs instance

# Wait for database to be ready
echo "Waiting for PostgreSQL..."
until PGPASSWORD=$POSTGRES_PASSWORD psql -h db -U $POSTGRES_USER -d $POSTGRES_DB -c '\q'; do
  echo "PostgreSQL is unavailable - sleeping"
  sleep 1
done

echo "PostgreSQL is up - executing setup"

# Create admin user if not exists
python -c "
import sys
sys.path.append('/app')
from app import app, db
from models import User
from werkzeug.security import generate_password_hash
import datetime

with app.app_context():
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    
    if not admin:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            created_at=datetime.datetime.utcnow()
        )
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully')
    else:
        print('Admin user already exists')

    # Create default system configuration
    from models import SystemConfig
    
    # Alert check interval (30 minutes)
    if not SystemConfig.query.filter_by(key='alert_check_interval').first():
        alert_interval = SystemConfig(
            key='alert_check_interval',
            value='30',
            description='Interval in minutes to check for new alerts'
        )
        db.session.add(alert_interval)
        db.session.commit()
        print('Default alert check interval set to 30 minutes')
    
    # 24-hour alert deduplication
    if not SystemConfig.query.filter_by(key='alert_dedup_hours').first():
        dedup_hours = SystemConfig(
            key='alert_dedup_hours',
            value='24',
            description='Number of hours to deduplicate alerts'
        )
        db.session.add(dedup_hours)
        db.session.commit()
        print('Default alert deduplication set to 24 hours')
"

echo "Initial database setup completed"