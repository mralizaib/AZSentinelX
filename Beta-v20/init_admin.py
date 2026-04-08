
from app import app, db
from models import User
from werkzeug.security import generate_password_hash
import datetime

def create_admin_user():
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
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
            print('Username: admin')
            print('Password: admin123')
        else:
            print('Admin user already exists')
            print('Username: admin')
            print('Password: admin123')

if __name__ == '__main__':
    create_admin_user()
