"""
Centralised permission helpers for AZ Sentinel X.

Usage — add a before_request guard to any blueprint:

    from routes.permissions import make_blueprint_permission_check
    dashboard_bp.before_request(make_blueprint_permission_check('dashboard'))
"""
import logging
from functools import wraps

from flask import (Blueprint, jsonify, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from models import MODULE_PERMISSIONS, User, UserPermission, db

logger = logging.getLogger(__name__)

permissions_bp = Blueprint('permissions', __name__)


# ---------------------------------------------------------------------------
# Core permission-check factory
# ---------------------------------------------------------------------------

def make_blueprint_permission_check(permission_key: str):
    """Return a before_request function that enforces *permission_key*.

    Returning None allows the request to proceed; returning a Response object
    short-circuits it (Flask before_request contract).
    """
    def _check():
        # Not yet logged in — let @login_required on the route handle it.
        if not current_user.is_authenticated:
            return None
        if not current_user.has_permission(permission_key):
            perm_label = MODULE_PERMISSIONS.get(permission_key, permission_key)
            logger.warning(
                "ACCESS DENIED  user='%s' permission='%s' path='%s'",
                current_user.username, permission_key, request.path
            )
            # API callers get JSON; page requests get the access-denied template.
            if (request.path.startswith('/api/')
                    or request.is_json
                    or request.headers.get('X-Requested-With') == 'XMLHttpRequest'):
                return jsonify({
                    'error': 'Access denied',
                    'permission_required': permission_key,
                }), 403
            return render_template(
                'access_denied.html',
                permission_label=perm_label,
            ), 403
        return None  # allow through
    _check.__name__ = f'check_permission_{permission_key}'
    return _check


# ---------------------------------------------------------------------------
# Permission management API  (admin-only)
# ---------------------------------------------------------------------------

@permissions_bp.route('/api/users/<int:user_id>/permissions', methods=['GET'])
@login_required
def get_user_permissions(user_id):
    """Return the granted permission keys for a user."""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    granted = [p.permission_key for p in user.permissions]
    return jsonify({
        'user_id': user_id,
        'username': user.username,
        'is_admin': user.is_admin(),
        'permissions': granted,
        'all_permissions': MODULE_PERMISSIONS,
    })


@permissions_bp.route('/api/users/<int:user_id>/permissions', methods=['PUT'])
@login_required
def set_user_permissions(user_id):
    """Replace the full permission set for a non-admin user."""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_admin():
        return jsonify({'message': 'Admins have all permissions — no change needed'}), 200

    data = request.get_json(silent=True) or {}
    new_keys = set(data.get('permissions', []))

    # Validate keys
    invalid = new_keys - set(MODULE_PERMISSIONS.keys())
    if invalid:
        return jsonify({'error': f'Unknown permission keys: {sorted(invalid)}'}), 400

    try:
        # Remove existing grants then insert fresh ones
        UserPermission.query.filter_by(user_id=user_id).delete()
        for key in new_keys:
            db.session.add(UserPermission(
                user_id=user_id,
                permission_key=key,
                granted_by=current_user.id,
            ))
        db.session.commit()
        logger.info(
            "Permissions updated  admin='%s' target_user='%s' permissions=%s",
            current_user.username, user.username, sorted(new_keys)
        )
        return jsonify({
            'message': 'Permissions updated successfully',
            'user_id': user_id,
            'permissions': sorted(new_keys),
        })
    except Exception as exc:
        db.session.rollback()
        logger.error("Error setting permissions for user %s: %s", user_id, exc)
        return jsonify({'error': str(exc)}), 500
