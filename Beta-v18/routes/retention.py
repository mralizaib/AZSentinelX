from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import logging
from datetime import datetime, timedelta
import json
from app import db
from models import RetentionPolicy
from retention_manager import RetentionManager

logger = logging.getLogger(__name__)

retention_bp = Blueprint('retention', __name__)

@retention_bp.route('/retention')
@login_required
def index():
    # Check if user is admin
    if not current_user.is_admin():
        return render_template('access_denied.html', message="Access denied: Admin privileges required so contact your System Administrator")
    
    # Get user's retention policies
    policies = RetentionPolicy.query.filter_by(user_id=current_user.id).all()
    return render_template('retention.html', policies=policies)

@retention_bp.route('/api/retention/policies', methods=['GET'])
@login_required
def get_policies():
    """Get all retention policies for the current user"""
    try:
        # Check if user is admin
        if not current_user.is_admin():
            return jsonify({'error': 'Access denied: Admin privileges required so contact your System Administrator'}), 403
            
        policies = RetentionPolicy.query.filter_by(user_id=current_user.id).all()
        
        policies_list = []
        for policy in policies:
            policies_list.append({
                'id': policy.id,
                'name': policy.name,
                'description': policy.description,
                'source_type': policy.source_type,
                'retention_days': policy.retention_days,
                'severity_levels': policy.get_severity_levels(),
                'rule_ids': policy.get_rule_ids(),
                'cron_schedule': policy.cron_schedule,
                'last_run': policy.last_run.isoformat() if policy.last_run else None,
                'enabled': policy.enabled,
                'created_at': policy.created_at.isoformat()
            })
        
        return jsonify(policies_list)
    except Exception as e:
        logger.error(f"Error getting retention policies: {str(e)}")
        return jsonify({'error': str(e)}), 500

@retention_bp.route('/api/retention/policies', methods=['POST'])
@login_required
def create_policy():
    """Create a new retention policy"""
    try:
        # Check if user is admin
        if not current_user.is_admin():
            return jsonify({'error': 'Access denied: Admin privileges required'}), 403
            
        data = request.json
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Policy name is required'}), 400
        
        if not data.get('source_type'):
            return jsonify({'error': 'Source type is required'}), 400
        
        if not data.get('retention_days'):
            return jsonify({'error': 'Retention period is required'}), 400
        
        # Create new policy
        new_policy = RetentionPolicy(
            user_id=current_user.id,
            name=data.get('name'),
            description=data.get('description', ''),
            source_type=data.get('source_type'),
            retention_days=int(data.get('retention_days')),
            cron_schedule=data.get('cron_schedule'),
            enabled=data.get('enabled', True)
        )
        
        # Set JSON fields
        if data.get('severity_levels'):
            new_policy.set_severity_levels(data.get('severity_levels'))
            
        if data.get('rule_ids'):
            new_policy.set_rule_ids(data.get('rule_ids'))
        
        # Save to database
        db.session.add(new_policy)
        db.session.commit()
        
        return jsonify({
            'id': new_policy.id,
            'name': new_policy.name,
            'message': 'Retention policy created successfully'
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating retention policy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@retention_bp.route('/api/retention/policies/<int:policy_id>', methods=['PUT'])
@login_required
def update_policy(policy_id):
    """Update an existing retention policy"""
    try:
        # Check if user is admin
        if not current_user.is_admin():
            return jsonify({'error': 'Access denied: Admin privileges required'}), 403
            
        policy = RetentionPolicy.query.filter_by(id=policy_id, user_id=current_user.id).first()
        
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        data = request.json
        
        # Update fields if provided
        if 'name' in data:
            policy.name = data['name']
        
        if 'description' in data:
            policy.description = data['description']
        
        if 'source_type' in data:
            policy.source_type = data['source_type']
        
        if 'retention_days' in data:
            policy.retention_days = int(data['retention_days'])
        
        if 'severity_levels' in data:
            policy.set_severity_levels(data['severity_levels'])
        
        if 'rule_ids' in data:
            policy.set_rule_ids(data['rule_ids'])
        
        if 'cron_schedule' in data:
            policy.cron_schedule = data['cron_schedule']
        
        if 'enabled' in data:
            policy.enabled = data['enabled']
        
        # Save changes
        db.session.commit()
        
        return jsonify({
            'id': policy.id,
            'message': 'Retention policy updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating retention policy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@retention_bp.route('/api/retention/policies/<int:policy_id>', methods=['DELETE'])
@login_required
def delete_policy(policy_id):
    """Delete a retention policy"""
    try:
        # Check if user is admin
        if not current_user.is_admin():
            return jsonify({'error': 'Access denied: Admin privileges required'}), 403
            
        policy = RetentionPolicy.query.filter_by(id=policy_id, user_id=current_user.id).first()
        
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        db.session.delete(policy)
        db.session.commit()
        
        return jsonify({
            'message': 'Retention policy deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting retention policy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@retention_bp.route('/api/retention/policies/<int:policy_id>/apply', methods=['POST'])
@login_required
def apply_policy(policy_id):
    """Apply a retention policy immediately"""
    try:
        # Check if user is admin
        if not current_user.is_admin():
            return jsonify({'error': 'Access denied: Admin privileges required'}), 403
            
        policy = RetentionPolicy.query.filter_by(id=policy_id, user_id=current_user.id).first()
        
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        # Apply the policy
        manager = RetentionManager()
        result = manager.apply_retention_policy(policy_id)
        
        if result['success']:
            return jsonify({
                'message': f"Retention policy applied successfully. Removed {result['details'][0].get('items_deleted', 0)} items.",
                'details': result
            })
        else:
            return jsonify({
                'error': f"Error applying retention policy: {result['errors']}",
                'details': result
            }), 500
    except Exception as e:
        logger.error(f"Error applying retention policy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@retention_bp.route('/api/retention/apply-all', methods=['POST'])
@login_required
def apply_all_policies():
    """Apply all enabled retention policies"""
    try:
        # Check if user is admin
        if not current_user.is_admin():
            return jsonify({'error': 'Access denied: Admin privileges required'}), 403
            
        # Apply all policies
        manager = RetentionManager()
        result = manager.apply_retention_policy()
        
        if result['success']:
            return jsonify({
                'message': f"Applied {result['policies_applied']} retention policies successfully",
                'details': result
            })
        else:
            return jsonify({
                'error': f"Error applying retention policies: {result['errors']}",
                'details': result
            }), 500
    except Exception as e:
        logger.error(f"Error applying all retention policies: {str(e)}")
        return jsonify({'error': str(e)}), 500