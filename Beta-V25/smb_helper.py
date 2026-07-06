"""
SMB connectivity helpers for SentinelX Log Backup.
Requires: pip install smbprotocol
"""
import logging
import os

logger = logging.getLogger(__name__)


def _parse_unc(path):
    """
    Parse '\\\\server\\share' or '//server/share' into (server, share).
    Returns (server_str, share_str).
    """
    p = path.strip().replace('/', '\\').lstrip('\\')
    parts = p.split('\\', 1)
    server = parts[0].strip()
    share  = parts[1].split('\\')[0].strip() if len(parts) > 1 else ''
    return server, share


def _make_unc(server, share):
    return f'\\\\{server}\\{share}'


def _register(server, username, password, domain):
    import smbclient
    smbclient.register_session(
        server,
        username=username or None,
        password=password or None,
        domain=domain or '',
        port=445,
        encrypt=False,
    )


def test_smb_connection(server_path, username, password, domain=''):
    """
    Attempt to connect and list the root of the share.
    Returns (success: bool, message: str).
    """
    try:
        import smbclient
        server, share = _parse_unc(server_path)
        if not server or not share:
            return False, 'Invalid path — use \\\\\\\\server\\\\share format (e.g. \\\\\\\\192.168.1.10\\\\backups).'
        _register(server, username, password, domain)
        unc = _make_unc(server, share)
        smbclient.listdir(unc)
        return True, (
            'Network share connected successfully. '
            'It is now ready for backup and restore operations.'
        )
    except ImportError:
        return False, 'smbprotocol package is not installed on the server.'
    except Exception as e:
        return False, f'Connection failed: {e}'


def list_smb_backups(server_path, username, password, domain=''):
    """
    Return a list of .ndjson.gz files in the root of the SMB share.
    Each entry: { name, unc_path, size_bytes, size_label, modified_ts }
    """
    import smbclient

    server, share = _parse_unc(server_path)
    _register(server, username, password, domain)
    unc = _make_unc(server, share)
    files = []
    try:
        for entry in smbclient.scandir(unc):
            if entry.is_file() and entry.name.lower().endswith('.ndjson.gz'):
                st = entry.stat()
                files.append({
                    'name':        entry.name,
                    'unc_path':    f'{unc}\\{entry.name}',
                    'size_bytes':  st.st_size,
                    'size_label':  _fmt_bytes(st.st_size),
                    'modified_ts': st.st_mtime,
                })
    except Exception as e:
        logger.error(f'list_smb_backups error: {e}')
    files.sort(key=lambda x: x['modified_ts'], reverse=True)
    return files


def upload_to_smb(local_file, server_path, username, password, domain='',
                  remote_filename=None):
    """
    Upload a local file to the root of the SMB share.
    Returns the remote UNC path on success.
    """
    import smbclient

    server, share = _parse_unc(server_path)
    _register(server, username, password, domain)
    fname      = remote_filename or os.path.basename(local_file)
    unc        = _make_unc(server, share)
    remote_unc = f'{unc}\\{fname}'

    with open(local_file, 'rb') as lf:
        with smbclient.open_file(remote_unc, mode='wb') as sf:
            while True:
                chunk = lf.read(1 * 1024 * 1024)   # 1 MB chunks
                if not chunk:
                    break
                sf.write(chunk)
    return remote_unc


def download_from_smb(remote_unc, local_path, server, username, password, domain=''):
    """
    Download a file from an SMB share to a local path.
    Returns local_path on success.
    """
    import smbclient

    _register(server, username, password, domain)
    with smbclient.open_file(remote_unc, mode='rb') as sf:
        with open(local_path, 'wb') as lf:
            while True:
                chunk = sf.read(1 * 1024 * 1024)
                if not chunk:
                    break
                lf.write(chunk)
    return local_path


def _fmt_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} PB'
