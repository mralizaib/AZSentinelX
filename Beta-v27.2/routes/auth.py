import base64
import io
import logging

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db, MODULE_PERMISSIONS

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)
MFA_ISSUER = 'REBIZ Sentinel X'


def _safe_next_page(value):
    """Only allow local redirects after successful authentication."""
    return value if value and value.startswith('/') and not value.startswith('//') else None


def _finish_login(user, remember=False, next_page=None):
    """Create the authenticated session after password/MFA verification."""
    login_user(user, remember=True)
    session.permanent = True
    session.pop('mfa_pending_user_id', None)
    session.pop('mfa_remember', None)
    session.pop('mfa_next', None)
    logger.info("User '%s' logged in (MFA=%s)", user.username, user.mfa_enabled)
    flash(f'Welcome back, {user.username}!', 'success')

    next_page = _safe_next_page(next_page)
    if not next_page:
        if user.role == 'dpcm':
            next_page = url_for('dvr_config.index')
        else:
            next_page = url_for('dashboard.index')
    return redirect(next_page)


def _pending_user():
    user_id = session.get('mfa_pending_user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


def _qr_data_uri(user):
    uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(
        name=user.email or user.username,
        issuer_name=MFA_ISSUER,
    )
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    encoded = base64.b64encode(buffer.getvalue()).decode('ascii')
    return f'data:image/png;base64,{encoded}'

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

        next_page = _safe_next_page(request.args.get('next'))

        # MFA is enforced before Flask-Login creates an authenticated session.
        # A pending user ID is stored only to bridge the two login steps.
        if user.mfa_enabled:
            if not user.mfa_secret:
                user.mfa_secret = pyotp.random_base32()
                user.mfa_configured = False
                db.session.commit()
            session['mfa_pending_user_id'] = user.id
            session['mfa_remember'] = remember
            session['mfa_next'] = next_page
            if user.mfa_configured:
                return redirect(url_for('auth.mfa_verify'))
            return redirect(url_for('auth.mfa_setup'))

        return _finish_login(user, remember=remember, next_page=next_page)

    return render_template('login.html', allow_remember=allow_remember)


@auth_bp.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    """Show a TOTP QR code and verify the first authenticator code."""
    user = _pending_user()
    if not user or not user.mfa_enabled or not user.mfa_secret:
        session.pop('mfa_pending_user_id', None)
        flash('Your MFA setup session has expired. Please sign in again.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = ''.join(ch for ch in request.form.get('otp', '') if ch.isdigit())
        if pyotp.TOTP(user.mfa_secret).verify(code, valid_window=1):
            user.mfa_configured = True
            db.session.commit()
            return _finish_login(
                user,
                remember=session.get('mfa_remember', False),
                next_page=session.get('mfa_next'),
            )
        flash('That code is invalid or expired. Check your authenticator and try again.', 'danger')

    return render_template(
        'mfa_setup.html',
        qr_data_uri=_qr_data_uri(user),
        secret=user.mfa_secret,
        username=user.username,
    )


@auth_bp.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    """Require a current six-digit TOTP code on every MFA-enabled login."""
    user = _pending_user()
    if not user or not user.mfa_enabled or not user.mfa_secret or not user.mfa_configured:
        session.pop('mfa_pending_user_id', None)
        flash('Your MFA session is invalid. Please sign in again.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = ''.join(ch for ch in request.form.get('otp', '') if ch.isdigit())
        if pyotp.TOTP(user.mfa_secret).verify(code, valid_window=1):
            return _finish_login(
                user,
                remember=session.get('mfa_remember', False),
                next_page=session.get('mfa_next'),
            )
        flash('That code is invalid or expired. Check your authenticator and try again.', 'danger')

    return render_template('mfa_verify.html', username=user.username)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # Registration is disabled - only admins can create new users
    flash('Registration is disabled. Please contact an administrator to create an account.', 'warning')
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/session/ping', methods=['POST'])
@login_required
def session_ping():
    """Heartbeat endpoint called by the JS keepalive every few minutes.
    Touching session.modified here (via before_request in app.py) resets
    the sliding idle-timeout so an active user is never logged out."""
    session.modified = True
    return {'ok': True}, 200


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
