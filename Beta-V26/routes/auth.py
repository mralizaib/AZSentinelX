from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db, MODULE_PERMISSIONS
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

def _remember_me_allowed():
    """Return True if the administrator has enabled persistent 'Remember Me' sessions."""
    try:
        from models import SystemConfig
        return SystemConfig.get_value('allow_remember_me', 'false').lower() == 'true'
    except Exception:
        return False


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    allow_remember = _remember_me_allowed()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Only honour "remember me" if the admin has enabled it
        remember = (allow_remember and bool(request.form.get('remember')))

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            logger.warning("Failed login attempt for username='%s' from %s",
                           username, request.remote_addr)
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('auth.login'))

        # Use a session cookie (no max_age) unless remember=True
        login_user(user, remember=remember)
        # Session is non-permanent by default → destroyed when browser closes
        session.permanent = remember
        logger.info("User '%s' logged in (remember=%s)", user.username, remember)
        flash(f'Welcome back, {user.username}!', 'success')

        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            # Role-based default landing pages
            if user.role == 'dpcm':
                next_page = url_for('dvr_config.index')
            else:
                next_page = url_for('dashboard.index')

        return redirect(next_page)

    return render_template('login.html', allow_remember=allow_remember)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # Registration is disabled - only admins can create new users
    flash('Registration is disabled. Please contact an administrator to create an account.', 'warning')
    return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Update email
        if email and email != current_user.email:
            # Check if email exists
            user = User.query.filter_by(email=email).first()
            if user and user.id != current_user.id:
                flash('Email already exists.', 'danger')
            else:
                current_user.email = email
                db.session.commit()
                flash('Email updated successfully.', 'success')
        
        # Update password
        if current_password and new_password:
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password updated successfully.', 'success')
        
        return redirect(url_for('auth.profile'))
    
    return render_template('profile.html')
