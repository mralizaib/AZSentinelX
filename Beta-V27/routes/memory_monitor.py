"""
Memory & Resource Monitor — shows live CPU, memory, disk, and per-process
usage of the Sentinel X application and the host it runs on.
"""
import logging
import os
import time
import threading
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

memory_monitor_bp = Blueprint('memory_monitor', __name__)

from routes.permissions import make_blueprint_permission_check
memory_monitor_bp.before_request(make_blueprint_permission_check('memory_monitor'))

# ---------------------------------------------------------------------------
# Rolling history buffer (last 60 data-points, ~1 per second)
# ---------------------------------------------------------------------------
_HISTORY_LEN = 60
_history_lock = threading.Lock()
_history = {
    'ts':           [],
    'mem_rss_mb':   [],
    'mem_vms_mb':   [],
    'mem_pct':      [],
    'cpu_pct':      [],
    'sys_mem_used': [],
    'sys_mem_pct':  [],
    'sys_cpu_pct':  [],
}

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False
    logger.warning("psutil not available — memory monitor will return limited data")


def _get_current_snapshot():
    """Collect one snapshot of process + system metrics."""
    if not _PSUTIL_OK:
        return {'error': 'psutil not installed'}

    try:
        proc = psutil.Process(os.getpid())

        # Process memory
        mem_info = proc.memory_info()
        mem_full  = proc.memory_full_info() if hasattr(proc, 'memory_full_info') else None
        mem_pct   = proc.memory_percent()
        cpu_pct   = proc.cpu_percent(interval=0.1)

        # Process threads / open files / connections
        try:
            num_threads = proc.num_threads()
        except Exception:
            num_threads = None
        try:
            num_fds = proc.num_fds()
        except Exception:
            num_fds = None
        try:
            connections = len(proc.connections())
        except Exception:
            connections = None

        # System memory
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # System CPU
        sys_cpu = psutil.cpu_percent(interval=0.1)
        sys_cpu_count = psutil.cpu_count()
        sys_cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)

        # Disk for the working directory
        disk = psutil.disk_usage(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        # Network I/O (system-wide)
        try:
            net = psutil.net_io_counters()
            net_data = {
                'bytes_sent_mb': round(net.bytes_sent / 1024 / 1024, 2),
                'bytes_recv_mb': round(net.bytes_recv / 1024 / 1024, 2),
            }
        except Exception:
            net_data = {}

        # Top child processes / threads
        try:
            children = []
            for child in proc.children(recursive=True):
                try:
                    children.append({
                        'pid':  child.pid,
                        'name': child.name(),
                        'mem_mb': round(child.memory_info().rss / 1024 / 1024, 2),
                        'cpu_pct': child.cpu_percent(interval=0),
                    })
                except Exception:
                    pass
        except Exception:
            children = []

        now = datetime.utcnow().strftime('%H:%M:%S')
        rss_mb = round(mem_info.rss / 1024 / 1024, 2)
        vms_mb = round(mem_info.vms / 1024 / 1024, 2)
        uss_mb = round(mem_full.uss / 1024 / 1024, 2) if mem_full and hasattr(mem_full, 'uss') else None
        pss_mb = round(mem_full.pss / 1024 / 1024, 2) if mem_full and hasattr(mem_full, 'pss') else None

        # Append to rolling history
        with _history_lock:
            for key, val in [
                ('ts',           now),
                ('mem_rss_mb',   rss_mb),
                ('mem_vms_mb',   vms_mb),
                ('mem_pct',      round(mem_pct, 2)),
                ('cpu_pct',      round(cpu_pct, 2)),
                ('sys_mem_used', round(vm.used / 1024 / 1024, 2)),
                ('sys_mem_pct',  round(vm.percent, 2)),
                ('sys_cpu_pct',  round(sys_cpu, 2)),
            ]:
                _history[key].append(val)
                if len(_history[key]) > _HISTORY_LEN:
                    _history[key].pop(0)

        return {
            'ts': now,
            'process': {
                'pid':         os.getpid(),
                'rss_mb':      rss_mb,
                'vms_mb':      vms_mb,
                'uss_mb':      uss_mb,
                'pss_mb':      pss_mb,
                'mem_pct':     round(mem_pct, 2),
                'cpu_pct':     round(cpu_pct, 2),
                'num_threads': num_threads,
                'num_fds':     num_fds,
                'connections': connections,
                'children':    children,
            },
            'system': {
                'mem_total_mb':   round(vm.total   / 1024 / 1024, 2),
                'mem_used_mb':    round(vm.used    / 1024 / 1024, 2),
                'mem_avail_mb':   round(vm.available / 1024 / 1024, 2),
                'mem_pct':        round(vm.percent, 2),
                'swap_total_mb':  round(swap.total / 1024 / 1024, 2),
                'swap_used_mb':   round(swap.used  / 1024 / 1024, 2),
                'swap_pct':       round(swap.percent, 2),
                'cpu_pct':        round(sys_cpu, 2),
                'cpu_count':      sys_cpu_count,
                'cpu_per_core':   sys_cpu_per_core,
                'disk_total_gb':  round(disk.total  / 1024 / 1024 / 1024, 2),
                'disk_used_gb':   round(disk.used   / 1024 / 1024 / 1024, 2),
                'disk_free_gb':   round(disk.free   / 1024 / 1024 / 1024, 2),
                'disk_pct':       round(disk.percent, 2),
                **net_data,
            },
        }
    except Exception as e:
        logger.error(f"Memory snapshot error: {e}", exc_info=True)
        return {'error': str(e)}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@memory_monitor_bp.route('/memory')
@login_required
def index():
    return render_template('memory_monitor.html')


@memory_monitor_bp.route('/api/memory/stats')
@login_required
def stats():
    """Return current snapshot + rolling history."""
    snap = _get_current_snapshot()
    with _history_lock:
        history = {k: list(v) for k, v in _history.items()}
    return jsonify({'snapshot': snap, 'history': history})


@memory_monitor_bp.route('/api/memory/top-processes')
@login_required
def top_processes():
    """Return top 10 system processes by RSS memory."""
    if not _PSUTIL_OK:
        return jsonify({'error': 'psutil not available'}), 503
    try:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent', 'status']):
            try:
                mi = p.info['memory_info']
                if mi:
                    procs.append({
                        'pid':    p.info['pid'],
                        'name':   p.info['name'],
                        'rss_mb': round(mi.rss / 1024 / 1024, 2),
                        'cpu_pct': p.info['cpu_percent'] or 0,
                        'status': p.info['status'],
                        'is_self': p.info['pid'] == os.getpid(),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        procs.sort(key=lambda x: x['rss_mb'], reverse=True)
        return jsonify({'processes': procs[:15]})
    except Exception as e:
        logger.error(f"top_processes error: {e}")
        return jsonify({'error': str(e)}), 500
