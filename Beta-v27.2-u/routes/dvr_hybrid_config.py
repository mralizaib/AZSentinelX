"""
DVR/NVR Hybrid Configuration Blueprint
Provides the UI and API endpoints for the ISAPI + Selenium hybrid workflow.
"""
import json
import logging
import threading
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from routes.permissions import make_blueprint_permission_check

logger = logging.getLogger(__name__)

dvr_hybrid_bp = Blueprint('dvr_hybrid', __name__)
dvr_hybrid_bp.before_request(make_blueprint_permission_check('dvr_config'))

# In-memory job store: {job_id: HybridProgress}
_jobs: dict = {}
_jobs_lock = threading.Lock()


# ── Main page ──────────────────────────────────────────────────────────────

@dvr_hybrid_bp.route('/dvr/hybrid')
@login_required
def index():
    from dvr_api import STATE_TIMEZONE, TZ_TO_HIKVISION
    return render_template(
        'dvr_hybrid_config.html',
        state_timezone_json=json.dumps(STATE_TIMEZONE),
        tz_to_hikvision_json=json.dumps(TZ_TO_HIKVISION),
    )


# ── Start a hybrid configuration job ──────────────────────────────────────

@dvr_hybrid_bp.route('/api/dvr/hybrid/start', methods=['POST'])
@login_required
def start_job():
    data = request.get_json() or {}

    # Validate required connection fields
    for f in ('ip', 'username', 'password'):
        if not data.get(f):
            return jsonify({'success': False, 'error': f'Missing field: {f}'}), 400

    conn = {
        'ip':        data['ip'],
        'port':      int(data.get('port', 80)),
        'username':  data['username'],
        'password':  data['password'],
        'use_https': data.get('use_https', False),
    }

    params = {
        'device_name':       data.get('device_name', ''),
        'city':              data.get('city', ''),
        'state':             data.get('state', ''),
        'hikvision_timezone': data.get('hikvision_timezone', ''),
        'ntp_server':        data.get('ntp_server', 'time.google.com'),
        'client_initials':   data.get('client_initials', ''),
        'dlt_password':      data.get('dlt_password', ''),
        'cms_password':      data.get('cms_password', ''),
        'create_manager':    data.get('create_manager', False),
        'manager_username':  data.get('manager_username', ''),
        'manager_password':  data.get('manager_password', ''),
        'selected_users':               data.get('selected_users', ['cms', 'dlt']),
        'channel_ids':                  data.get('channel_ids') or [],
        'format_hdds':                  data.get('format_hdds', False),
        'admin_verification_password':  data.get('admin_verification_password', ''),
    }

    job_id = str(uuid.uuid4())

    from dvr_hybrid import HybridProgress, HybridDVRConfigurator, build_report
    progress = HybridProgress()
    progress.config_params = params

    with _jobs_lock:
        _jobs[job_id] = progress

    def _worker():
        try:
            hc = HybridDVRConfigurator(conn, params, progress)
            hc.run()
            # Attach final report to progress for easy retrieval
            progress._report = build_report(progress, conn, params)
        except Exception as e:
            logger.error(f"[Hybrid worker] Unhandled error: {e}", exc_info=True)
            progress.phase = "error"
            progress.error = str(e)

    t = threading.Thread(target=_worker, daemon=True,
                         name=f"hybrid-{job_id[:8]}")
    t.start()

    return jsonify({'success': True, 'job_id': job_id})


# ── Poll job status ────────────────────────────────────────────────────────

@dvr_hybrid_bp.route('/api/dvr/hybrid/status/<job_id>', methods=['GET'])
@login_required
def job_status(job_id):
    with _jobs_lock:
        progress = _jobs.get(job_id)
    if progress is None:
        return jsonify({'success': False, 'error': 'Job not found'}), 404

    return jsonify({'success': True, 'status': progress.to_dict()})


# ── Retrieve full report ───────────────────────────────────────────────────

@dvr_hybrid_bp.route('/api/dvr/hybrid/report/<job_id>', methods=['GET'])
@login_required
def job_report(job_id):
    with _jobs_lock:
        progress = _jobs.get(job_id)
    if progress is None:
        return jsonify({'success': False, 'error': 'Job not found'}), 404

    if progress.phase not in ('done', 'error'):
        return jsonify({'success': False,
                        'error': 'Job still running',
                        'phase': progress.phase}), 202

    report = getattr(progress, '_report', None)
    if report is None:
        return jsonify({'success': False, 'error': 'Report not yet available'}), 202

    return jsonify({'success': True, 'report': report})


# ── Quick connectivity test (reuses existing DVRClient) ───────────────────

@dvr_hybrid_bp.route('/api/dvr/hybrid/test-connect', methods=['POST'])
@login_required
def test_connect():
    data = request.get_json() or {}
    for f in ('ip', 'username', 'password'):
        if not data.get(f):
            return jsonify({'success': False, 'error': f'Missing: {f}'}), 400

    ip       = data['ip']
    port     = int(data.get('port', 80))
    username = data['username']
    password = data['password']
    use_https = data.get('use_https', False)

    # ── Step 1: TCP reachability check (fast, 5s timeout) ─────────────────
    import socket
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        sock.close()
    except socket.timeout:
        return jsonify({
            'success': False,
            'error': (f'Device unreachable — connection to {ip}:{port} timed out. '
                      f'Check the IP/hostname, port, firewall rules, and that port forwarding is active.'),
        }), 503
    except (socket.gaierror, socket.herror) as e:
        return jsonify({
            'success': False,
            'error': f'DNS / hostname resolution failed for "{ip}": {e}',
        }), 503
    except ConnectionRefusedError:
        return jsonify({
            'success': False,
            'error': (f'Connection refused on {ip}:{port} — the port is closed or the '
                      f'HTTP service is not running on the device.'),
        }), 503
    except OSError as e:
        return jsonify({
            'success': False,
            'error': f'Network error reaching {ip}:{port} — {e}',
        }), 503

    # ── Step 2: ISAPI authentication + device info ─────────────────────────
    try:
        import requests as req_lib
        from requests.auth import HTTPDigestAuth
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        scheme = 'https' if use_https else 'http'
        url = f'{scheme}://{ip}:{port}/ISAPI/System/deviceInfo'
        r = req_lib.get(url, auth=HTTPDigestAuth(username, password),
                        timeout=15, verify=False)

        if r.status_code == 200:
            # Full device info via DVRClient
            from dvr_api import DVRClient
            client = DVRClient(ip=ip, port=port, username=username,
                               password=password, use_https=use_https)
            info = client.get_device_info()
            return jsonify({'success': True, 'device_info': info})

        if r.status_code in (401, 403):
            return jsonify({
                'success': False,
                'error': (f'Authentication failed (HTTP {r.status_code}) — '
                          f'check username and password.'),
            }), 401

        return jsonify({
            'success': False,
            'error': (f'Device responded with HTTP {r.status_code}. '
                      f'It may not support ISAPI or may need HTTPS enabled.'),
        }), 502

    except req_lib.exceptions.ConnectTimeout:
        return jsonify({
            'success': False,
            'error': (f'ISAPI request timed out to {ip}:{port}. '
                      f'The port is open but the device is not responding to HTTP — '
                      f'check if HTTPS is required.'),
        }), 503
    except req_lib.exceptions.SSLError as e:
        return jsonify({
            'success': False,
            'error': f'SSL/TLS error — try toggling the "Use HTTPS" option. Detail: {e}',
        }), 503
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
