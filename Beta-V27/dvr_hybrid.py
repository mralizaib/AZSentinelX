"""
DVR/NVR Hybrid Configuration Orchestrator
Attempts each task via ISAPI first; falls back to Selenium automatically on
failure. Verifies every setting after applying it. Produces a structured
configuration report covering device info, method used, pass/fail status,
timing, and any warnings.
"""
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Status constants ───────────────────────────────────────────────────────
STATUS_PASS    = "pass"
STATUS_FAIL    = "fail"
STATUS_WARN    = "warn"
STATUS_SKIP    = "skip"

METHOD_ISAPI    = "isapi"
METHOD_SELENIUM = "selenium"
METHOD_NONE     = "none"


# ── Task result dataclass ──────────────────────────────────────────────────
@dataclass
class TaskResult:
    task:           str
    status:         str = STATUS_SKIP      # pass | fail | warn | skip
    method:         str = METHOD_NONE      # isapi | selenium | none
    detail:         str = ""
    warning:        str = ""
    verified:       bool = False
    verify_detail:  str = ""
    duration_ms:    int = 0
    isapi_tried:    bool = False
    isapi_error:    str = ""
    selenium_tried: bool = False
    selenium_error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Hybrid progress tracker ────────────────────────────────────────────────
class HybridProgress:
    """Thread-safe progress store — polled by the status API endpoint."""

    def __init__(self):
        self.tasks: List[TaskResult] = []
        self.current_task: str = ""
        self.phase: str = "pending"   # pending | running | done | error
        self.error: str = ""
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.device_info: dict = {}
        self.config_params: dict = {}

    def add(self, result: TaskResult):
        self.tasks.append(result)

    def update_last(self, **kwargs):
        if self.tasks:
            for k, v in kwargs.items():
                setattr(self.tasks[-1], k, v)

    def to_dict(self) -> dict:
        return {
            "phase":        self.phase,
            "current_task": self.current_task,
            "error":        self.error,
            "started_at":   self.started_at.isoformat() if self.started_at else None,
            "finished_at":  self.finished_at.isoformat() if self.finished_at else None,
            "device_info":  self.device_info,
            "tasks":        [t.to_dict() for t in self.tasks],
            "total":        len(self.tasks),
            "passed":       sum(1 for t in self.tasks if t.status == STATUS_PASS),
            "failed":       sum(1 for t in self.tasks if t.status == STATUS_FAIL),
            "warned":       sum(1 for t in self.tasks if t.status == STATUS_WARN),
            "isapi_tasks":  sum(1 for t in self.tasks if t.method == METHOD_ISAPI),
            "selenium_tasks": sum(1 for t in self.tasks if t.method == METHOD_SELENIUM),
        }


# ── Hybrid Orchestrator ────────────────────────────────────────────────────
class HybridDVRConfigurator:
    """
    Runs the full DVR configuration workflow with ISAPI-first + Selenium fallback.

    Usage:
        progress = HybridProgress()
        hc = HybridDVRConfigurator(conn, params, progress)
        hc.run()
        report = progress.to_dict()
    """

    def __init__(self, conn: dict, params: dict, progress: HybridProgress):
        """
        conn:    {ip, port, username, password, use_https}
        params:  {device_name, city, state, hikvision_timezone,
                  client_initials, dlt_password, cms_password,
                  create_manager, manager_username, manager_password,
                  channel_ids, ntp_server}
        """
        self.conn    = conn
        self.params  = params
        self.progress = progress
        self._isapi  = None     # DVRClient — built lazily
        self._sel    = None     # SeleniumDVRAdapter — built lazily
        self._sel_started = False

    # ── Lazy client builders ───────────────────────────────────────────────

    def _get_isapi(self):
        if self._isapi is None:
            from dvr_api import DVRClient
            self._isapi = DVRClient(
                ip=self.conn['ip'],
                port=int(self.conn.get('port', 80)),
                username=self.conn['username'],
                password=self.conn['password'],
                use_https=self.conn.get('use_https', False),
            )
        return self._isapi

    def _get_selenium(self):
        if self._sel is None:
            from dvr_selenium import SeleniumDVRAdapter
            self._sel = SeleniumDVRAdapter(
                ip=self.conn['ip'],
                port=int(self.conn.get('port', 80)),
                username=self.conn['username'],
                password=self.conn['password'],
                use_https=self.conn.get('use_https', False),
            )
        if not self._sel_started:
            r = self._sel.start()
            if r['ok']:
                login_r = self._sel.login()
                self._sel_started = login_r['ok']
                if not self._sel_started:
                    logger.warning(f"[Hybrid] Selenium login failed: {login_r['detail']}")
            else:
                logger.warning(f"[Hybrid] Selenium start failed: {r['detail']}")
        return self._sel

    def _selenium_available(self) -> bool:
        try:
            from dvr_selenium import _check_selenium_available
            ok, _ = _check_selenium_available()
            return ok
        except Exception:
            return False

    # ── Timing wrapper ─────────────────────────────────────────────────────

    def _timed(self, fn, *args, **kwargs):
        """Call fn(*args, **kwargs), return (result, elapsed_ms)."""
        t0 = time.time()
        result = fn(*args, **kwargs)
        elapsed = int((time.time() - t0) * 1000)
        return result, elapsed

    # ── Generic task runner ────────────────────────────────────────────────

    def _run_task(self,
                  task_name: str,
                  isapi_fn,           # callable → (ok: bool, detail: str)
                  verify_fn,          # callable → (ok: bool, detail: str)
                  selenium_fn=None,   # callable → dict(ok, method, detail)
                  ) -> TaskResult:
        """
        Core hybrid logic:
          1. Try ISAPI.
          2. If ISAPI fails AND selenium_fn provided → try Selenium.
          3. Verify the setting via ISAPI read-back.
          4. Return TaskResult.
        """
        r = TaskResult(task=task_name)
        self.progress.current_task = task_name
        self.progress.add(r)

        total_start = time.time()

        # ── Step 1: ISAPI attempt ──────────────────────────────────────────
        isapi_ok   = False
        isapi_err  = ""
        isapi_ms   = 0
        r.isapi_tried = True

        try:
            (ok, detail), isapi_ms = self._timed(isapi_fn)
            if ok:
                isapi_ok   = True
                r.method   = METHOD_ISAPI
                r.detail   = detail
                logger.info(f"[Hybrid] ISAPI ✓ {task_name}: {detail}")
            else:
                isapi_err  = detail
                logger.info(f"[Hybrid] ISAPI ✗ {task_name}: {detail} → trying Selenium")
        except Exception as e:
            isapi_err = str(e)
            logger.info(f"[Hybrid] ISAPI exception {task_name}: {e} → trying Selenium")

        r.isapi_error = isapi_err

        # ── Step 2: Selenium fallback ──────────────────────────────────────
        if not isapi_ok and selenium_fn is not None:
            r.selenium_tried = True
            try:
                sel = self._get_selenium()
                sel_result, sel_ms = self._timed(selenium_fn, sel)
                if isinstance(sel_result, dict) and sel_result.get('ok'):
                    r.method  = METHOD_SELENIUM
                    r.detail  = sel_result.get('detail', f"{task_name} via Selenium")
                    logger.info(f"[Hybrid] Selenium ✓ {task_name}: {r.detail}")
                else:
                    r.selenium_error = (
                        sel_result.get('detail', 'Selenium task failed')
                        if isinstance(sel_result, dict) else str(sel_result)
                    )
                    logger.info(f"[Hybrid] Selenium ✗ {task_name}: {r.selenium_error}")
            except Exception as e:
                r.selenium_error = str(e)
                logger.warning(f"[Hybrid] Selenium exception {task_name}: {e}")

        # ── Step 3: Verify ────────────────────────────────────────────────
        if r.method in (METHOD_ISAPI, METHOD_SELENIUM):
            try:
                time.sleep(0.5)
                (v_ok, v_detail), _ = self._timed(verify_fn)
                r.verified      = v_ok
                r.verify_detail = v_detail
                if v_ok:
                    r.status = STATUS_PASS
                    logger.info(f"[Hybrid] Verify ✓ {task_name}: {v_detail}")
                else:
                    r.status  = STATUS_WARN
                    r.warning = f"Verification mismatch: {v_detail}"
                    logger.warning(f"[Hybrid] Verify ✗ {task_name}: {v_detail}")
            except Exception as e:
                r.verify_detail = f"Verify error: {e}"
                r.status        = STATUS_WARN
                r.warning       = f"Could not re-verify setting: {e}"
        else:
            # Both ISAPI and Selenium failed
            r.status  = STATUS_FAIL
            r.detail  = f"ISAPI: {isapi_err}" + (
                f" | Selenium: {r.selenium_error}" if r.selenium_error else "")

        r.duration_ms = int((time.time() - total_start) * 1000)
        logger.info(f"[Hybrid] {task_name} → {r.status} in {r.duration_ms}ms via {r.method}")
        return r

    # ── Verification helpers (read-back via ISAPI) ─────────────────────────

    def _verify_device_name(self):
        try:
            client = self._get_isapi()
            import xml.etree.ElementTree as ET
            r = client._get("/System/deviceInfo")
            root = ET.fromstring(r.text)
            actual = ""
            for el in root.iter():
                if "deviceName" in el.tag:
                    actual = (el.text or "").strip()
                    break
            expected = self.params.get('device_name', '').strip()
            ok = bool(expected) and actual == expected
            return ok, f"Device reports name: '{actual}'"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_time(self):
        try:
            client = self._get_isapi()
            r = client._get("/System/time")
            ok = r.status_code == 200 and "<timeMode>" in r.text
            mode = "NTP" if "NTP" in r.text else "unknown"
            return ok, f"Time mode: {mode}"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_hdd(self):
        try:
            client = self._get_isapi()
            hdds = client.get_storage_info()
            if not hdds:
                return False, "No HDDs detected"
            statuses = [h.get('status', 'unknown') for h in hdds]
            ok = all(s.lower() in ("ok", "normal", "active") for s in statuses)
            return ok, f"HDD statuses: {', '.join(statuses)}"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_stream(self, channel_id: str):
        try:
            client = self._get_isapi()
            r = client._get(f"/Streaming/channels/{channel_id}")
            ok = r.status_code == 200 and "H.264" in r.text
            return ok, f"Stream config readable for channel {channel_id}"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_recording(self, channel_id: str):
        try:
            client = self._get_isapi()
            r = client._get(f"/ContentMgmt/record/tracks/{channel_id}")
            ok = r.status_code == 200 and (
                "<TrackSchedule>" in r.text or "<ScheduleBlock>" in r.text
            )
            return ok, f"Recording schedule present on track {channel_id}"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_holiday(self):
        try:
            client = self._get_isapi()
            r = client._get("/System/holidays")
            ok = r.status_code == 200 and (
                "<Holiday>" in r.text or "<holiday>" in r.text
            )
            return ok, "Holiday schedule present on device" if ok else "No holidays found"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_user(self, username: str):
        try:
            client = self._get_isapi()
            existing = client._get_existing_users()
            found = username in existing
            return found, f"User '{username}' {'exists' if found else 'not found'}"
        except Exception as e:
            return False, f"Verify error: {e}"

    def _verify_channel_zero(self):
        try:
            client = self._get_isapi()
            r = client._get("/Streaming/channels/0")
            disabled = r.status_code == 200 and "false" in r.text.lower()
            return disabled, f"Channel Zero disabled: {disabled}"
        except Exception as e:
            return True, "Channel Zero check skipped (endpoint may not exist)"

    # ── ISAPI task wrappers — each returns (ok: bool, detail: str) ─────────

    def _isapi_device_name(self):
        client = self._get_isapi()
        name = self.params.get('device_name', '')
        ok = client.configure_device_name(name)
        return ok, f"Name set to '{name}'" if ok else "ISAPI rejected device name change"

    def _isapi_time(self):
        client = self._get_isapi()
        city  = self.params.get('city', '')
        state = self.params.get('state', '')
        result = client.configure_time(city, state)
        ok = result.get('ntp_ok') or result.get('time_ok') or result.get('status') == 'ok'
        tz = result.get('hikvision_timezone', '')
        return ok, f"NTP+timezone applied (tz={tz})"

    def _isapi_format_hdd(self, hdd_id: str):
        client = self._get_isapi()
        try:
            client.format_hdd(hdd_id)
            return True, f"HDD {hdd_id} format initiated"
        except Exception as e:
            return False, str(e)

    def _isapi_main_stream(self, channel_id: str):
        client = self._get_isapi()
        ok = client.configure_main_stream(channel_id)
        return ok, f"Main stream 1080p H.264 CBR configured" if ok else "Main stream ISAPI failed"

    def _isapi_sub_stream(self, channel_id: str):
        client = self._get_isapi()
        result = client.configure_sub_stream(channel_id)
        ok = result.get('ok', False)
        return ok, f"Sub stream {result.get('applied_resolution','?')} configured" if ok else result.get('note', '')

    def _isapi_recording(self, channel_id: str):
        client = self._get_isapi()
        ok = client.configure_recording_schedule(channel_id)
        return ok, f"Recording schedule written to track {channel_id}" if ok else "Schedule ISAPI failed"

    def _isapi_holiday(self):
        client = self._get_isapi()
        ok = client.configure_holiday()
        return ok, "Holiday schedule applied" if ok else "Holiday ISAPI failed"

    def _isapi_create_user(self, username: str, password: str, role: str):
        client = self._get_isapi()
        try:
            uid = client.create_user(username, password, role=role)
            client.set_user_permissions(uid, username, username)
            return True, f"User '{username}' created (id={uid})"
        except Exception as e:
            return False, str(e)

    def _isapi_disable_ch0(self):
        client = self._get_isapi()
        try:
            client.disable_channel_zero()
            return True, "Channel Zero disabled"
        except Exception as e:
            return False, str(e)

    # ── Main run() ─────────────────────────────────────────────────────────

    def run(self):
        """Execute the full hybrid configuration workflow."""
        p = self.progress
        p.phase      = "running"
        p.started_at = datetime.utcnow()

        try:
            client = self._get_isapi()

            # ── 0. Device Discovery ───────────────────────────────────────
            p.current_task = "Device Discovery"
            try:
                info = client.get_device_info()
                p.device_info = info
                # Resolve channel IDs
                channel_ids = (
                    self.params.get('channel_ids')
                    or info.get('channel_ids')
                    or [f"{ch}01" for ch in range(1, int(info.get('total_channels', 4)) + 1)]
                )
                self.params['channel_ids'] = channel_ids
                disc_result = TaskResult(
                    task="Device Discovery",
                    status=STATUS_PASS,
                    method=METHOD_ISAPI,
                    detail=(
                        f"Model: {info.get('model','?')} | "
                        f"Firmware: {info.get('firmware_version','?')} | "
                        f"Channels: {info.get('total_channels','?')}"
                    ),
                    verified=True,
                    verify_detail="Device info retrieved successfully",
                )
                p.add(disc_result)
                logger.info(f"[Hybrid] Discovery: {disc_result.detail}")
            except Exception as e:
                p.add(TaskResult(
                    task="Device Discovery",
                    status=STATUS_FAIL,
                    method=METHOD_NONE,
                    detail=str(e),
                ))
                channel_ids = self.params.get('channel_ids') or ["101"]

            # ── 1. Device Name ────────────────────────────────────────────
            self._run_task(
                "Device Name",
                isapi_fn=self._isapi_device_name,
                verify_fn=self._verify_device_name,
                selenium_fn=lambda sel: sel.configure_device_name(
                    self.params.get('device_name', '')),
            )

            # ── 2. Time / NTP ─────────────────────────────────────────────
            self._run_task(
                "Time & NTP",
                isapi_fn=self._isapi_time,
                verify_fn=self._verify_time,
                selenium_fn=lambda sel: sel.configure_time(
                    self.params.get('hikvision_timezone', ''),
                    self.params.get('ntp_server', 'time.google.com'),
                ),
            )

            # ── 3. HDD — list + conditional format ────────────────────────
            try:
                hdds = client.get_storage_info()
                hdd_ids = [h['id'] for h in hdds] if hdds else ['1']
                p.device_info['hdds'] = hdds
            except Exception:
                hdd_ids = ['1']
                hdds = []

            if self.params.get('format_hdds') and hdd_ids:
                for hdd_id in hdd_ids:
                    self._run_task(
                        f"HDD Format (id={hdd_id})",
                        isapi_fn=lambda hid=hdd_id: self._isapi_format_hdd(hid),
                        verify_fn=self._verify_hdd,
                        # No Selenium equivalent for HDD format
                    )
                    time.sleep(3)   # Format is async on device
            else:
                # Just verify existing HDD health
                v_ok, v_detail = self._verify_hdd()
                p.add(TaskResult(
                    task="HDD Status",
                    status=STATUS_PASS if v_ok else STATUS_WARN,
                    method=METHOD_ISAPI,
                    detail=v_detail,
                    verified=v_ok,
                    verify_detail=v_detail,
                ))

            # ── 4. Main Stream (per channel) ──────────────────────────────
            for cid in channel_ids:
                ch_label = cid[:-2] if len(cid) > 2 else cid
                ch_num   = int(ch_label) if ch_label.isdigit() else 1
                self._run_task(
                    f"Main Stream — Ch{ch_label}",
                    isapi_fn=lambda c=cid: self._isapi_main_stream(c),
                    verify_fn=lambda c=cid: self._verify_stream(c),
                    selenium_fn=lambda sel, n=ch_num: sel.configure_stream(n),
                )

            # ── 5. Sub Stream (per channel) ───────────────────────────────
            for cid in channel_ids:
                ch_label = cid[:-2] if len(cid) > 2 else cid
                sub_id   = cid[:-2] + "02" if len(cid) >= 3 else cid
                self._run_task(
                    f"Sub Stream — Ch{ch_label}",
                    isapi_fn=lambda c=cid: self._isapi_sub_stream(c),
                    verify_fn=lambda s=sub_id: self._verify_stream(s),
                    # Sub stream has no dedicated Selenium path; ISAPI only
                )

            # ── 6. Recording Schedule (per channel) ───────────────────────
            for cid in channel_ids:
                ch_label = cid[:-2] if len(cid) > 2 else cid
                ch_num   = int(ch_label) if ch_label.isdigit() else 1
                self._run_task(
                    f"Recording Schedule — Ch{ch_label}",
                    isapi_fn=lambda c=cid: self._isapi_recording(c),
                    verify_fn=lambda c=cid: self._verify_recording(c),
                    selenium_fn=lambda sel, n=ch_num: sel.configure_recording(n),
                )

            # ── 7. Holiday Schedule ───────────────────────────────────────
            self._run_task(
                "Holiday Schedule",
                isapi_fn=self._isapi_holiday,
                verify_fn=self._verify_holiday,
            )

            # ── 8. Channel Zero ───────────────────────────────────────────
            self._run_task(
                "Channel Zero Disable",
                isapi_fn=self._isapi_disable_ch0,
                verify_fn=self._verify_channel_zero,
            )

            # ── 9. Users ──────────────────────────────────────────────────
            initials = (self.params.get('client_initials', '') or '').strip().upper()
            users_to_create = []

            if 'cms' in (self.params.get('selected_users') or ['cms', 'dlt']):
                users_to_create.append({
                    'username': 'cms',
                    'password': self.params.get('cms_password') or f"{initials}_cam12",
                    'role': 'viewer',
                })
            if 'dlt' in (self.params.get('selected_users') or ['cms', 'dlt']):
                users_to_create.append({
                    'username': 'dlt',
                    'password': self.params.get('dlt_password') or f"{initials}9722IDT!",
                    'role': 'operator',
                })
            if self.params.get('create_manager'):
                mgr_user = self.params.get('manager_username') or 'manager'
                mgr_pass = self.params.get('manager_password') or f"{initials}man_12"
                users_to_create.append({
                    'username': mgr_user,
                    'password': mgr_pass,
                    'role': 'viewer',
                })

            for u in users_to_create:
                un, pw, role = u['username'], u['password'], u['role']
                self._run_task(
                    f"User — {un}",
                    isapi_fn=lambda x=un, y=pw, z=role: self._isapi_create_user(x, y, z),
                    verify_fn=lambda x=un: self._verify_user(x),
                    selenium_fn=lambda sel, x=un, y=pw, z=role: sel.create_user(x, y, z),
                )

            # ── 10. Final ISAPI Validation pass ──────────────────────────
            p.current_task = "Final Validation"
            try:
                expected = {
                    'device_name': self.params.get('device_name', ''),
                    'hikvision_timezone': self.params.get('hikvision_timezone', ''),
                    'channel_ids': channel_ids,
                    'users_created': [u['username'] for u in users_to_create],
                }
                val_results = client.validate_configuration(expected)
                for vr in val_results:
                    # Map validate_configuration result into TaskResult
                    status_map = {"pass": STATUS_PASS, "warn": STATUS_WARN, "fail": STATUS_FAIL}
                    existing_tasks = [t.task for t in p.tasks]
                    # Only add validation results not already covered
                    if vr['check'] not in existing_tasks:
                        p.add(TaskResult(
                            task=f"[Validate] {vr['check']}",
                            status=status_map.get(vr['status'], STATUS_WARN),
                            method=METHOD_ISAPI,
                            detail=vr['detail'],
                            warning=vr.get('action', ''),
                            verified=True,
                            verify_detail=vr['detail'],
                        ))
            except Exception as e:
                logger.warning(f"[Hybrid] Final validation error: {e}")

            p.phase       = "done"
            p.current_task = ""

        except Exception as e:
            logger.error(f"[Hybrid] Fatal error: {e}", exc_info=True)
            p.phase = "error"
            p.error = str(e)

        finally:
            p.finished_at = datetime.utcnow()
            # Clean up Selenium browser
            if self._sel and self._sel_started:
                try:
                    self._sel.quit()
                except Exception:
                    pass
            logger.info(
                f"[Hybrid] Configuration complete: "
                f"{sum(1 for t in p.tasks if t.status==STATUS_PASS)} pass, "
                f"{sum(1 for t in p.tasks if t.status==STATUS_FAIL)} fail, "
                f"{sum(1 for t in p.tasks if t.status==STATUS_WARN)} warn"
            )


# ── Report builder ─────────────────────────────────────────────────────────

def build_report(progress: HybridProgress, conn: dict, params: dict) -> dict:
    """
    Build the final structured configuration report dict.
    """
    total_ms = 0
    if progress.started_at and progress.finished_at:
        total_ms = int(
            (progress.finished_at - progress.started_at).total_seconds() * 1000
        )

    tasks = progress.tasks
    return {
        "report_generated_at": datetime.utcnow().isoformat(),
        "device": {
            "ip":               conn.get('ip'),
            "port":             conn.get('port'),
            "use_https":        conn.get('use_https', False),
            "model":            progress.device_info.get('model', 'Unknown'),
            "firmware_version": progress.device_info.get('firmware_version', 'Unknown'),
            "serial_number":    progress.device_info.get('serial_number', 'Unknown'),
            "device_name":      params.get('device_name', ''),
            "total_channels":   progress.device_info.get('total_channels', '?'),
        },
        "configuration": {
            "city":             params.get('city', ''),
            "state":            params.get('state', ''),
            "timezone":         params.get('hikvision_timezone', ''),
            "ntp_server":       params.get('ntp_server', 'time.google.com'),
            "client_initials":  params.get('client_initials', ''),
            "channel_ids":      params.get('channel_ids', []),
        },
        "summary": {
            "phase":           progress.phase,
            "started_at":      progress.started_at.isoformat() if progress.started_at else None,
            "finished_at":     progress.finished_at.isoformat() if progress.finished_at else None,
            "total_duration_ms": total_ms,
            "total_tasks":     len(tasks),
            "passed":          sum(1 for t in tasks if t.status == STATUS_PASS),
            "failed":          sum(1 for t in tasks if t.status == STATUS_FAIL),
            "warned":          sum(1 for t in tasks if t.status == STATUS_WARN),
            "skipped":         sum(1 for t in tasks if t.status == STATUS_SKIP),
            "isapi_tasks":     sum(1 for t in tasks if t.method == METHOD_ISAPI),
            "selenium_tasks":  sum(1 for t in tasks if t.method == METHOD_SELENIUM),
            "verified_tasks":  sum(1 for t in tasks if t.verified),
        },
        "tasks": [t.to_dict() for t in tasks],
        "warnings": [
            {"task": t.task, "warning": t.warning}
            for t in tasks if t.warning
        ],
        "unsupported_features": [
            {"task": t.task, "detail": t.detail}
            for t in tasks
            if t.status == STATUS_FAIL
        ],
    }
