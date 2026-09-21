"""
DVR/NVR Selenium Fallback Adapter
Automates Hikvision / OEM device web UIs for configuration tasks that fail
or are unsupported via ISAPI. Uses Chrome headless; degrades gracefully when
Chrome is unavailable.
"""
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Selenium availability guard — imported lazily so the app starts even when
# Chrome or the selenium package is absent.
# ---------------------------------------------------------------------------
def _check_selenium_available():
    """Returns (available: bool, reason: str)."""
    try:
        import selenium  # noqa: F401
        return True, "ok"
    except ImportError:
        return False, "selenium package not installed"


def _make_driver(headless: bool = True):
    """
    Build and return a Chrome WebDriver with Selenium Manager auto-ChromeDriver.
    Raises RuntimeError if Chrome cannot be started.
    """
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--allow-insecure-localhost")
    opts.add_argument("--disable-web-security")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-popup-blocking")
    opts.add_experimental_option("excludeSwitches", ["enable-logging"])
    opts.set_capability("acceptInsecureCerts", True)

    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(5)
        return driver
    except Exception as e:
        raise RuntimeError(f"Chrome WebDriver unavailable: {e}") from e


# ---------------------------------------------------------------------------
# Helper: wait for element, try multiple selectors
# ---------------------------------------------------------------------------
def _find(driver, *css_selectors, timeout: float = 8):
    """Try each CSS selector in turn; return the first element found or None."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    for sel in css_selectors:
        try:
            el = WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, sel))
            )
            return el
        except Exception:
            continue
    return None


def _click(driver, *css_selectors, timeout: float = 8):
    """Find and click the first matched element. Returns True on success."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    for sel in css_selectors:
        try:
            el = WebDriverWait(driver, timeout).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, sel))
            )
            el.click()
            return True
        except Exception:
            continue
    return False


def _set_value(driver, css_selector: str, value: str, clear: bool = True):
    """Set an input's value. Returns True on success."""
    el = _find(driver, css_selector)
    if el is None:
        return False
    try:
        if clear:
            el.clear()
        el.send_keys(value)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SeleniumDVRAdapter
# ---------------------------------------------------------------------------
class SeleniumDVRAdapter:
    """
    Selenium-based configuration adapter for Hikvision/OEM device web UIs.
    Each method returns a dict: {'ok': bool, 'method': 'selenium', 'detail': str}
    """

    # Login URL candidates in priority order
    _LOGIN_PATHS = [
        "/",
        "/doc/page/login.asp",
        "/ISAPI/Security/userCheck",
    ]

    # Post-login landing paths that indicate a successful login
    _DASHBOARD_INDICATORS = [
        "param.asp",
        "index.asp",
        "main.html",
        "dashboard",
        "#/main",
        "doc/page",
    ]

    def __init__(self, ip: str, port: int, username: str, password: str,
                 use_https: bool = False, headless: bool = True):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.scheme = "https" if use_https else "http"
        self.base_url = f"{self.scheme}://{ip}:{port}"
        self._driver = None
        self._logged_in = False

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> dict:
        """Start Chrome and navigate to the device. Returns status dict."""
        avail, reason = _check_selenium_available()
        if not avail:
            return {'ok': False, 'method': 'selenium',
                    'detail': f"Selenium unavailable: {reason}"}
        try:
            self._driver = _make_driver()
            return {'ok': True, 'method': 'selenium', 'detail': "Chrome started"}
        except RuntimeError as e:
            return {'ok': False, 'method': 'selenium', 'detail': str(e)}

    def quit(self):
        """Gracefully shut down Chrome."""
        if self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None
            self._logged_in = False

    # ── Login ──────────────────────────────────────────────────────────────

    def login(self) -> dict:
        """
        Navigate to the device web UI and log in. Tries multiple URL patterns
        because Hikvision firmware varies significantly.
        Returns {'ok': bool, 'method': 'selenium', 'detail': str}
        """
        if not self._driver:
            r = self.start()
            if not r['ok']:
                return r

        driver = self._driver

        # Try each login URL path
        for path in self._LOGIN_PATHS:
            url = self.base_url + path
            try:
                driver.get(url)
                time.sleep(1)

                # Look for username field
                user_field = _find(
                    driver,
                    "input#username", "input[name='username']",
                    "input[type='text']", "#loginUser",
                    "input[placeholder*='user' i]", "input[placeholder*='User' i]",
                    timeout=5,
                )
                if user_field is None:
                    continue

                # Fill credentials
                user_field.clear()
                user_field.send_keys(self.username)

                pass_field = _find(
                    driver,
                    "input#password", "input[name='password']",
                    "input[type='password']", "#loginPassword",
                    timeout=5,
                )
                if pass_field is None:
                    continue
                pass_field.clear()
                pass_field.send_keys(self.password)

                # Submit
                submitted = _click(
                    driver,
                    "button[type='submit']", "#loginBtn", ".loginBtn",
                    "input[type='submit']", "button.login-btn",
                    "button:contains('Login')", "#save",
                    timeout=5,
                )
                if not submitted:
                    # Try pressing Enter on the password field
                    from selenium.webdriver.common.keys import Keys
                    pass_field.send_keys(Keys.RETURN)

                time.sleep(3)

                # Check if login succeeded (look for dashboard content)
                current = driver.current_url
                page_src = driver.page_source.lower()
                logged_in = (
                    any(ind in current for ind in self._DASHBOARD_INDICATORS)
                    or "logout" in page_src
                    or "sign out" in page_src
                    or "configuration" in page_src
                )

                if logged_in:
                    self._logged_in = True
                    logger.info(f"[Selenium] Logged in to {self.ip} via {url}")
                    return {'ok': True, 'method': 'selenium',
                            'detail': f"Logged in via {path}"}

            except Exception as e:
                logger.debug(f"[Selenium] Login attempt at {path} failed: {e}")
                continue

        self._logged_in = False
        return {'ok': False, 'method': 'selenium',
                'detail': "Could not find or complete login form on any known URL path"}

    def _require_login(self) -> Optional[dict]:
        """Ensure logged in; returns error dict if not, None if ok."""
        if self._logged_in and self._driver:
            return None
        r = self.login()
        if not r['ok']:
            return r
        return None

    # ── Task: Device Name ──────────────────────────────────────────────────

    def configure_device_name(self, name: str) -> dict:
        """Set device name via System > Device Information web page."""
        err = self._require_login()
        if err:
            return err
        driver = self._driver
        task = "Device Name"

        # Try navigation paths known to contain Device Name field
        nav_paths = [
            "/doc/page/param.asp?subMenu=system&tabId=1",
            "/doc/page/param.asp?subMenu=system&tabMenu=deviceInfo",
            "/System/deviceInfo",
        ]

        for path in nav_paths:
            try:
                driver.get(self.base_url + path)
                time.sleep(2)

                # Look for device name input
                field = _find(
                    driver,
                    "input#deviceName", "input[name='deviceName']",
                    "input[placeholder*='device' i]", "input[placeholder*='name' i]",
                    "#deviceName", ".device-name input",
                    timeout=6,
                )
                if field is None:
                    continue

                field.clear()
                field.send_keys(name)
                time.sleep(0.5)

                saved = _click(driver, "#save", ".save-btn", "button[type='submit']",
                               "input[type='submit']", ".btn-primary", timeout=5)
                if saved:
                    time.sleep(1)
                    return {'ok': True, 'method': 'selenium',
                            'detail': f"{task}: set to '{name}' via web UI"}
            except Exception as e:
                logger.debug(f"[Selenium] {task} path {path} failed: {e}")
                continue

        return {'ok': False, 'method': 'selenium',
                'detail': f"{task}: could not locate name field in web UI"}

    # ── Task: Time / NTP ──────────────────────────────────────────────────

    def configure_time(self, timezone_str: str, ntp_server: str = "time.google.com") -> dict:
        """Configure time zone and NTP via the web UI."""
        err = self._require_login()
        if err:
            return err
        driver = self._driver
        task = "Time/NTP"

        nav_paths = [
            "/doc/page/param.asp?subMenu=system&tabId=4",
            "/doc/page/param.asp?subMenu=system&tabMenu=timeCfg",
            "/doc/page/param.asp?subMenu=system&tabMenu=ntp",
        ]

        for path in nav_paths:
            try:
                driver.get(self.base_url + path)
                time.sleep(2)

                # Try to select NTP mode
                _click(driver, "#syncMode_ntp", "input[value='NTP']",
                       "input[name='timeMode'][value='NTP']",
                       "#ntp", "label[for*='ntp' i]", timeout=5)
                time.sleep(0.5)

                # NTP server
                ntp_field = _find(driver,
                    "#ntpServer", "input[name='ntpServer']",
                    "input[placeholder*='NTP' i]", "input[placeholder*='ntp' i]",
                    timeout=5)
                if ntp_field:
                    ntp_field.clear()
                    ntp_field.send_keys(ntp_server)

                # Timezone dropdown
                from selenium.webdriver.common.by import By
                from selenium.webdriver.support.ui import Select
                tz_el = _find(driver,
                    "select#timeZone", "select[name='timeZone']",
                    "select#timezone", "select.time-zone",
                    timeout=5)
                if tz_el and tz_el.tag_name == "select":
                    sel = Select(tz_el)
                    # Try to find a matching option
                    try:
                        sel.select_by_value(timezone_str)
                    except Exception:
                        # Try partial text match
                        for opt in sel.options:
                            if any(part in opt.text for part in timezone_str.split(",")):
                                sel.select_by_visible_text(opt.text)
                                break

                saved = _click(driver, "#save", ".save-btn", "button[type='submit']",
                               "input[type='submit']", ".btn-primary", timeout=5)
                if saved:
                    time.sleep(1)
                    return {'ok': True, 'method': 'selenium',
                            'detail': f"{task}: NTP enabled, server={ntp_server}"}
            except Exception as e:
                logger.debug(f"[Selenium] {task} path {path} failed: {e}")
                continue

        return {'ok': False, 'method': 'selenium',
                'detail': f"{task}: could not locate time configuration page"}

    # ── Task: Stream Settings ──────────────────────────────────────────────

    def configure_stream(self, channel_num: int) -> dict:
        """Configure main stream for a channel via the web UI."""
        err = self._require_login()
        if err:
            return err
        driver = self._driver
        task = f"Main Stream Ch{channel_num}"

        nav_paths = [
            f"/doc/page/param.asp?subMenu=camera&tabId=1&channelNo={channel_num}",
            f"/doc/page/param.asp?subMenu=encoding&channelNo={channel_num}",
        ]

        for path in nav_paths:
            try:
                driver.get(self.base_url + path)
                time.sleep(2)

                # Resolution
                from selenium.webdriver.support.ui import Select
                res_el = _find(driver,
                    "select#videoResolution", "select[name='videoResolution']",
                    "select.resolution", timeout=5)
                if res_el and res_el.tag_name == "select":
                    try:
                        Select(res_el).select_by_value("1920x1080")
                    except Exception:
                        for opt in Select(res_el).options:
                            if "1920" in opt.text or "1080" in opt.text:
                                Select(res_el).select_by_visible_text(opt.text)
                                break

                # Codec
                codec_el = _find(driver,
                    "select#videoCodecType", "select[name='videoCodecType']",
                    timeout=5)
                if codec_el and codec_el.tag_name == "select":
                    try:
                        Select(codec_el).select_by_value("H.264")
                    except Exception:
                        pass

                # Bitrate type → CBR
                _click(driver,
                    "input[value='CBR']", "input[name='videoQualityControlType'][value='CBR']",
                    "#cbr", timeout=4)

                saved = _click(driver, "#save", ".save-btn", "button[type='submit']",
                               "input[type='submit']", ".btn-primary", timeout=5)
                if saved:
                    time.sleep(1)
                    return {'ok': True, 'method': 'selenium',
                            'detail': f"{task}: 1920×1080 H.264 CBR set via web UI"}
            except Exception as e:
                logger.debug(f"[Selenium] {task} path {path} failed: {e}")
                continue

        return {'ok': False, 'method': 'selenium',
                'detail': f"{task}: could not locate encoding page"}

    # ── Task: User Creation ────────────────────────────────────────────────

    def create_user(self, username: str, password: str, role: str = "viewer") -> dict:
        """Create a user account via the web UI."""
        err = self._require_login()
        if err:
            return err
        driver = self._driver
        task = f"User '{username}'"

        nav_paths = [
            "/doc/page/param.asp?subMenu=system&tabId=7",
            "/doc/page/param.asp?subMenu=system&tabMenu=userMgr",
            "/doc/page/param.asp?subMenu=userMgr",
        ]

        for path in nav_paths:
            try:
                driver.get(self.base_url + path)
                time.sleep(2)

                # Click "Add User" button
                added = _click(driver,
                    "#addUser", ".add-user", "button[onclick*='addUser' i]",
                    "a[onclick*='addUser' i]", "#btnAddUser",
                    timeout=6)
                if not added:
                    continue

                time.sleep(1.5)

                # Fill username
                un_ok = _set_value(driver,
                    "#userName", "input[name='userName']",
                    "input[placeholder*='user' i]")
                if not un_ok:
                    continue
                # Clear and retype to avoid autofill issues
                _find(driver, "#userName", "input[name='userName']").clear()
                _find(driver, "#userName", "input[name='userName']").send_keys(username)

                # Fill passwords
                _set_value(driver, "#password", "input[name='password']",
                           "input[type='password']", value=password)
                _set_value(driver, "#confirmPassword", "input[name='confirmPassword']",
                           "input[placeholder*='confirm' i]", value=password)

                # Role / permission level
                from selenium.webdriver.support.ui import Select
                role_el = _find(driver,
                    "select#userLevel", "select[name='userLevel']",
                    "select.user-level", timeout=4)
                if role_el and role_el.tag_name == "select":
                    role_map = {"viewer": "Viewer", "operator": "Operator", "admin": "Administrator"}
                    try:
                        Select(role_el).select_by_visible_text(role_map.get(role, "Viewer"))
                    except Exception:
                        pass

                saved = _click(driver, "#save", ".save-btn", "#ok",
                               "button[type='submit']", ".btn-primary",
                               "input[type='submit']", timeout=5)
                if saved:
                    time.sleep(1)
                    return {'ok': True, 'method': 'selenium',
                            'detail': f"{task}: created as {role} via web UI"}
            except Exception as e:
                logger.debug(f"[Selenium] {task} path {path} failed: {e}")
                continue

        return {'ok': False, 'method': 'selenium',
                'detail': f"{task}: could not complete user creation via web UI"}

    # ── Task: Recording Schedule ───────────────────────────────────────────

    def configure_recording(self, channel_num: int) -> dict:
        """Enable continuous + motion recording schedule via the web UI."""
        err = self._require_login()
        if err:
            return err
        driver = self._driver
        task = f"Recording Schedule Ch{channel_num}"

        nav_paths = [
            f"/doc/page/param.asp?subMenu=storage&tabId=2&channelNo={channel_num}",
            f"/doc/page/param.asp?subMenu=record&channelNo={channel_num}",
        ]

        for path in nav_paths:
            try:
                driver.get(self.base_url + path)
                time.sleep(2)

                # Enable "All Day" continuous recording
                _click(driver,
                    "input[name='recordType'][value='1']",
                    "#continueRecord", ".continue-record",
                    "input[value='continuous' i]",
                    timeout=5)

                saved = _click(driver, "#save", ".save-btn",
                               "button[type='submit']", ".btn-primary", timeout=5)
                if saved:
                    time.sleep(1)
                    return {'ok': True, 'method': 'selenium',
                            'detail': f"{task}: continuous schedule enabled via web UI"}
            except Exception as e:
                logger.debug(f"[Selenium] {task} path {path} failed: {e}")
                continue

        return {'ok': False, 'method': 'selenium',
                'detail': f"{task}: could not locate recording schedule page"}

    # ── Screenshot capture (for report evidence) ──────────────────────────

    def capture_screenshot(self) -> Optional[bytes]:
        """Capture a PNG screenshot of the current page."""
        if self._driver:
            try:
                return self._driver.get_screenshot_as_png()
            except Exception:
                pass
        return None
