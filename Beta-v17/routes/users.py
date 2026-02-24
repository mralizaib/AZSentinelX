from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import logging
from werkzeug.security import generate_password_hash
from app import db
from models import User

logger = logging.getLogger(__name__)

users_bp = Blueprint('users', __name__)

@users_bp.route('/users')
@login_required
def index():
    # Only admins can access this page
    if not current_user.is_admin():
        flash('Access denied: Admin privileges required.', 'danger')
        return redirect(url_for('dashboard.index'))
    
    # Get all users
    users = User.query.all()
    return render_template('users.html', users=users)

@users_bp.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Get all users (admin only)"""
    try:
        if not current_user.is_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        users = User.query.all()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'created_at': user.created_at.isoformat()
            })
        
        return jsonify(users_list)
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/api/users', methods=['POST'])
@login_required
def create_user():
    """Create a new user (admin only)"""
    try:
        if not current_user.is_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        data = request.json
        
        # Validate required fields
        if not data.get('username'):
            return jsonify({'error': 'Username is required'}), 400
        
        if not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        
        if not data.get('password'):
            return jsonify({'error': 'Password is required'}), 400
        
        if not data.get('role'):
            return jsonify({'error': 'Role is required'}), 400
        
        # Check if username exists
        user = User.query.filter_by(username=data['username']).first()
        if user:
            return jsonify({'error': 'Username already exists'}), 400
        
        # Check if email exists
        user = User.query.filter_by(email=data['email']).first()
        if user:
            return jsonify({'error': 'Email already exists'}), 400
        
        # Validate role
        role = data['role']
        if role not in ['admin', 'agent']:
            return jsonify({'error': 'Invalid role'}), 400
        
        # Create new user
        new_user = User(
            username=data['username'],
            email=data['email'],
            role=role
        )
        new_user.set_password(data['password'])
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'id': new_user.id,
            'username': new_user.username,
            'message': 'User created successfully'
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update an existing user (admin only or self)"""
    try:
        # Allow users to update their own information or admins to update any user
        if not current_user.is_admin() and current_user.id != user_id:
            return jsonify({'error': 'You can only update your own account'}), 403
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.json
        
        # Update fields if provided
        if 'email' in data:
            # Check if email exists
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'error': 'Email already exists'}), 400
            
            user.email = data['email']
        
        # Only admins can change roles
        if 'role' in data and current_user.is_admin():
            role = data['role']
            if role not in ['admin', 'agent']:
                return jsonify({'error': 'Invalid role'}), 400
            
            user.role = role
        
        # Update password if provided
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        db.session.commit()
        
        return jsonify({
            'id': user.id,
            'message': 'User updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    try:
        if not current_user.is_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        # Prevent deleting self
        if current_user.id == user_id:
            return jsonify({'error': 'You cannot delete your own account'}), 400
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        return jsonify({'error': str(e)}), 500
