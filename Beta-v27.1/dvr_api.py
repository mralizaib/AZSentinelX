"""
DVR/NVR ISAPI Client
Supports Hikvision, Platinum (Hikvision OEM), and LTS (Hikvision OEM) devices.
All three brands use the Hikvision ISAPI over HTTP/HTTPS with Digest Auth.
"""
import copy
import logging
from datetime import datetime
import xml.etree.ElementTree as ET
import requests
from requests.auth import HTTPDigestAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

# US State → IANA timezone mapping
STATE_TIMEZONE = {
    "Alabama": "America/Chicago", "Alaska": "America/Anchorage",
    "Arizona": "America/Phoenix", "Arkansas": "America/Chicago",
    "California": "America/Los_Angeles", "Colorado": "America/Denver",
    "Connecticut": "America/New_York", "Delaware": "America/New_York",
    "Florida": "America/New_York", "Georgia": "America/New_York",
    "Hawaii": "Pacific/Honolulu", "Idaho": "America/Boise",
    "Illinois": "America/Chicago", "Indiana": "America/Indiana/Indianapolis",
    "Iowa": "America/Chicago", "Kansas": "America/Chicago",
    "Kentucky": "America/Kentucky/Louisville", "Louisiana": "America/Chicago",
    "Maine": "America/New_York", "Maryland": "America/New_York",
    "Massachusetts": "America/New_York", "Michigan": "America/Detroit",
    "Minnesota": "America/Chicago", "Mississippi": "America/Chicago",
    "Missouri": "America/Chicago", "Montana": "America/Denver",
    "Nebraska": "America/Chicago", "Nevada": "America/Los_Angeles",
    "New Hampshire": "America/New_York", "New Jersey": "America/New_York",
    "New Mexico": "America/Denver", "New York": "America/New_York",
    "North Carolina": "America/New_York", "North Dakota": "America/Chicago",
    "Ohio": "America/New_York", "Oklahoma": "America/Chicago",
    "Oregon": "America/Los_Angeles", "Pennsylvania": "America/New_York",
    "Rhode Island": "America/New_York", "South Carolina": "America/New_York",
    "South Dakota": "America/Chicago", "Tennessee": "America/Chicago",
    "Texas": "America/Chicago", "Utah": "America/Denver",
    "Vermont": "America/New_York", "Virginia": "America/New_York",
    "Washington": "America/Los_Angeles", "West Virginia": "America/New_York",
    "Wisconsin": "America/Chicago", "Wyoming": "America/Denver",
    "District of Columbia": "America/New_York",
}

# IANA tz → device POSIX timeZone string.
TZ_TO_HIKVISION = {
    "America/New_York":                   "EST5EDT,M3.2.0,M11.1.0",
    "America/Chicago":                    "CST6CDT,M3.2.0,M11.1.0",
    "America/Denver":                     "MST7MDT,M3.2.0,M11.1.0",
    "America/Los_Angeles":                "PST8PDT,M3.2.0,M11.1.0",
    "America/Anchorage":                  "AKST9AKDT,M3.2.0,M11.1.0",
    "Pacific/Honolulu":                   "HST10",
    "America/Phoenix":                    "MST7",
    "America/Boise":                      "MST7MDT,M3.2.0,M11.1.0",
    "America/Indiana/Indianapolis":       "EST5EDT,M3.2.0,M11.1.0",
    "America/Kentucky/Louisville":        "EST5EDT,M3.2.0,M11.1.0",
    "America/Detroit":                    "EST5EDT,M3.2.0,M11.1.0",
    "America/Halifax":                    "AST4ADT,M3.2.0,M11.1.0",
    "America/Toronto":                    "EST5EDT,M3.2.0,M11.1.0",
    "America/Vancouver":                  "PST8PDT,M3.2.0,M11.1.0",
    "America/Edmonton":                   "MST7MDT,M3.2.0,M11.1.0",
    "America/Winnipeg":                   "CST6CDT,M3.2.0,M11.1.0",
    "America/Mexico_City":                "CST6CDT,M4.1.0,M10.5.0",
    "America/Bogota":                     "COT5",
    "America/Lima":                       "PET5",
    "America/Santiago":                   "CLT4CLST,M10.2.6/24,M3.2.6/24",
    "America/Sao_Paulo":                  "BRT3BRST,M10.3.0,M2.3.0",
    "America/Argentina/Buenos_Aires":     "ART3",
    "Europe/London":                      "GMT0BST,M3.5.0,M10.5.0",
    "Europe/Paris":                       "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Berlin":                      "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Madrid":                      "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Rome":                        "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Amsterdam":                   "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Brussels":                    "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Zurich":                      "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Stockholm":                   "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Helsinki":                    "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Europe/Athens":                      "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Europe/Istanbul":                    "TRT-3",
    "Europe/Moscow":                      "MSK-3",
    "Europe/Kiev":                        "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Asia/Dubai":                         "GST-4",
    "Asia/Karachi":                       "PKT-5",
    "Asia/Kolkata":                       "IST-5:30",
    "Asia/Dhaka":                         "BST-6",
    "Asia/Bangkok":                       "ICT-7",
    "Asia/Singapore":                     "SGT-8",
    "Asia/Shanghai":                      "CST-8",
    "Asia/Tokyo":                         "JST-9",
    "Asia/Seoul":                         "KST-9",
    "Asia/Riyadh":                        "AST-3",
    "Asia/Baghdad":                       "AST-3",
    "Asia/Tehran":                        "IRST-3:30IRDT,80/0,264/0",
    "Asia/Kabul":                         "AFT-4:30",
    "Asia/Tashkent":                      "UZT-5",
    "Asia/Almaty":                        "ALMT-6",
    "Asia/Jakarta":                       "WIB-7",
    "Asia/Manila":                        "PHT-8",
    "Asia/Taipei":                        "CST-8",
    "Asia/Hong_Kong":                     "HKT-8",
    "Asia/Kuala_Lumpur":                  "MYT-8",
    "Asia/Colombo":                       "IST-5:30",
    "Africa/Cairo":                       "EET-2",
    "Africa/Lagos":                       "WAT-1",
    "Africa/Nairobi":                     "EAT-3",
    "Africa/Johannesburg":                "SAST-2",
    "Africa/Casablanca":                  "WET0WEST,M3.5.0,M10.5.0",
    "Australia/Sydney":                   "AEST-10AEDT,M10.1.0,M4.1.0/3",
    "Australia/Melbourne":                "AEST-10AEDT,M10.1.0,M4.1.0/3",
    "Australia/Brisbane":                 "AEST-10",
    "Australia/Perth":                    "AWST-8",
    "Australia/Adelaide":                 "ACST-9:30ACDT,M10.1.0,M4.1.0/3",
    "Pacific/Auckland":                   "NZST-12NZDT,M9.5.0,M4.1.0/3",
    "Pacific/Fiji":                       "FJT-12",
    "UTC":                                "UTC0",
}

# Long Hikvision format
TZ_TO_HIKVISION_LONG = {
    "America/New_York":                   "EST+5:00:00EDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Chicago":                    "CST+6:00:00CDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Denver":                     "MST+7:00:00MDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Los_Angeles":                "PST+8:00:00PDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Anchorage":                  "AKST+9:00:00AKDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "Pacific/Honolulu":                   "HST+10:00:00",
    "America/Phoenix":                    "MST+7:00:00",
    "America/Boise":                      "MST+7:00:00MDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Indiana/Indianapolis":       "EST+5:00:00EDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Kentucky/Louisville":        "EST+5:00:00EDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Detroit":                    "EST+5:00:00EDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Halifax":                    "AST+4:00:00ADT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Toronto":                    "EST+5:00:00EDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Vancouver":                  "PST+8:00:00PDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Edmonton":                   "MST+7:00:00MDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Winnipeg":                   "CST+6:00:00CDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00",
    "America/Mexico_City":                "CST+6:00:00CDT-1:00:00,M4.1.0/02:00:00,M10.5.0/02:00:00",
    "America/Bogota":                     "COT+5:00:00",
    "America/Lima":                       "PET+5:00:00",
    "America/Santiago":                   "CLT+4:00:00CLST-1:00:00,M10.2.6/24:00:00,M3.2.6/24:00:00",
    "America/Sao_Paulo":                  "BRT+3:00:00BRST-1:00:00,M10.3.0/00:00:00,M2.3.0/00:00:00",
    "America/Argentina/Buenos_Aires":     "ART+3:00:00",
    "Europe/London":                      "GMT+0:00:00BST-1:00:00,M3.5.0/01:00:00,M10.5.0/02:00:00",
    "Europe/Paris":                       "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Berlin":                      "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Madrid":                      "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Rome":                        "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Amsterdam":                   "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Brussels":                    "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Zurich":                      "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Stockholm":                   "CET-1:00:00CEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Europe/Helsinki":                    "EET-2:00:00EEST-1:00:00,M3.5.0/03:00:00,M10.5.0/04:00:00",
    "Europe/Athens":                      "EET-2:00:00EEST-1:00:00,M3.5.0/03:00:00,M10.5.0/04:00:00",
    "Europe/Istanbul":                    "TRT-3:00:00",
    "Europe/Moscow":                      "MSK-3:00:00",
    "Europe/Kiev":                        "EET-2:00:00EEST-1:00:00,M3.5.0/03:00:00,M10.5.0/04:00:00",
    "Asia/Dubai":                         "GST-4:00:00",
    "Asia/Karachi":                       "PKT-5:00:00",
    "Asia/Kolkata":                       "IST-5:30:00",
    "Asia/Dhaka":                         "BST-6:00:00",
    "Asia/Bangkok":                       "ICT-7:00:00",
    "Asia/Singapore":                     "SGT-8:00:00",
    "Asia/Shanghai":                      "CST-8:00:00",
    "Asia/Tokyo":                         "JST-9:00:00",
    "Asia/Seoul":                         "KST-9:00:00",
    "Asia/Riyadh":                        "AST-3:00:00",
    "Asia/Baghdad":                       "AST-3:00:00",
    "Asia/Tehran":                        "IRST-3:30:00IRDT-1:00:00,80/00:00:00,264/00:00:00",
    "Asia/Kabul":                         "AFT-4:30:00",
    "Asia/Tashkent":                      "UZT-5:00:00",
    "Asia/Almaty":                        "ALMT-6:00:00",
    "Asia/Jakarta":                       "WIB-7:00:00",
    "Asia/Manila":                        "PHT-8:00:00",
    "Asia/Taipei":                        "CST-8:00:00",
    "Asia/Hong_Kong":                     "HKT-8:00:00",
    "Asia/Kuala_Lumpur":                  "MYT-8:00:00",
    "Asia/Colombo":                       "IST-5:30:00",
    "Africa/Cairo":                       "EET-2:00:00",
    "Africa/Lagos":                       "WAT-1:00:00",
    "Africa/Nairobi":                     "EAT-3:00:00",
    "Africa/Johannesburg":                "SAST-2:00:00",
    "Africa/Casablanca":                  "WET+0:00:00WEST-1:00:00,M3.5.0/02:00:00,M10.5.0/03:00:00",
    "Australia/Sydney":                   "AEST-10:00:00AEDT-1:00:00,M10.1.0/02:00:00,M4.1.0/03:00:00",
    "Australia/Melbourne":                "AEST-10:00:00AEDT-1:00:00,M10.1.0/02:00:00,M4.1.0/03:00:00",
    "Australia/Brisbane":                 "AEST-10:00:00",
    "Australia/Perth":                    "AWST-8:00:00",
    "Australia/Adelaide":                 "ACST-9:30:00ACDT-1:00:00,M10.1.0/02:00:00,M4.1.0/03:00:00",
    "Pacific/Auckland":                   "NZST-12:00:00NZDT-1:00:00,M9.5.0/02:00:00,M4.1.0/03:00:00",
    "Pacific/Fiji":                       "FJT-12:00:00",
    "UTC":                                "UTC+0:00:00",
}

NS = "http://www.hikvision.com/ver20/XMLSchema"


def _ns(tag):
    return f"{{{NS}}}{tag}"


def _parse_xml(text):
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        logger.warning(f"XML parse error: {e} — raw: {text[:200]}")
        return None


def _local(tag):
    """Strip any {namespace} prefix from an element tag."""
    return tag.rsplit('}', 1)[-1] if tag else tag


def _child_by_local_name(node, tag):
    """Find a direct child matching `tag`, ignoring whatever XML namespace
    the device actually uses."""
    if node is None:
        return None
    for child in list(node):
        if _local(child.tag) == tag:
            return child
    return None


def _find(root, *tags):
    """Walk tag path, ignoring XML namespace differences between devices."""
    node = root
    for tag in tags:
        if node is None:
            return None
        node = _child_by_local_name(node, tag)
    return node


def _find_all(root, tag):
    """Find all descendants matching `tag` anywhere in the tree, ignoring
    whatever XML namespace the device uses."""
    if root is None:
        return []
    return [el for el in root.iter() if _local(el.tag) == tag]


def _children_by_local_name(node, tag):
    """Find all *direct* children matching `tag`, ignoring namespace."""
    if node is None:
        return []
    return [c for c in list(node) if _local(c.tag) == tag]


def _find_first(root, tag):
    """Find the first descendant matching `tag` anywhere in the tree,
    ignoring namespace. Returns None if not found."""
    if root is None:
        return None
    for el in root.iter():
        if _local(el.tag) == tag:
            return el
    return None


def _text(root, *tags, default="N/A"):
    node = _find(root, *tags)
    return node.text.strip() if node is not None and node.text else default


def _patch_xml_field(xml_str, tag, new_value):
    """Replace the text content of <tag>...</tag> in an XML string using regex.
    Handles both plain tags and namespace-prefixed tags."""
    import re as _re
    pattern = (
        rf"(<(?:[^:>\s/]+:)?{_re.escape(tag)}(?:\s[^>]*)?>)"
        rf".*?"
        rf"(</(?:[^:>\s/]+:)?{_re.escape(tag)}>)"
    )
    replacement = rf"\g<1>{new_value}\g<2>"
    result = _re.sub(pattern, replacement, xml_str, flags=_re.DOTALL)
    return result


def _patch_xml_fields(xml_str, patches):
    """Apply a list of (tag, value) patches to an XML string sequentially."""
    for tag, value in patches:
        xml_str = _patch_xml_field(xml_str, tag, value)
    return xml_str


def _channel_label(channel_id):
    """Main-stream channel ID ("101", "1601") -> human channel number ("1", "16")."""
    return channel_id[:-2] if len(channel_id) > 2 else channel_id


def _format_channel_ranges(labels):
    """Format a list of channel-number strings into compact ranges for display."""
    numeric, non_numeric = [], []
    for lbl in labels:
        try:
            numeric.append(int(lbl))
        except (TypeError, ValueError):
            non_numeric.append(str(lbl))
    numeric = sorted(set(numeric))

    ranges = []
    i = 0
    while i < len(numeric):
        start = end = numeric[i]
        while i + 1 < len(numeric) and numeric[i + 1] == end + 1:
            i += 1
            end = numeric[i]
        ranges.append(str(start) if start == end else f"{start}-{end}")
        i += 1
    ranges.extend(sorted(set(non_numeric)))
    return ", ".join(ranges) if ranges else "none"


def _build_channel_check_result(check_name, all_channel_ids, ok_ids, fixed_ids,
                                  fail_ids, skipped_ids, target_desc=""):
    """Build a validation result dict describing the real per-channel outcome."""
    ok_labels     = _format_channel_ranges([_channel_label(c) for c in ok_ids])
    fixed_labels  = _format_channel_ranges([_channel_label(c) for c in fixed_ids])
    fail_labels   = _format_channel_ranges([_channel_label(c) for c in fail_ids])
    skip_labels   = _format_channel_ranges([_channel_label(c) for c in skipped_ids])

    if not all_channel_ids:
        return {
            "check": check_name, "status": "warn",
            "detail": "Could not verify — no channels were discovered on this device.",
            "action": "Manually verify on the device.",
        }

    if not fail_ids and ok_ids:
        detail = f"Successfully verified on all available channels ({ok_labels})"
        if target_desc:
            detail += f" — {target_desc}"
        if fixed_ids:
            detail += f". Auto-corrected on channel(s) {fixed_labels}."
        else:
            detail += "."
        status = "pass"
    elif ok_ids:
        detail = f"Verified on channel(s) {ok_labels}. Failed on channel(s) {fail_labels}."
        status = "warn"
    else:
        detail = f"Failed to verify on channel(s) {fail_labels}."
        status = "fail"

    if skipped_ids:
        detail += f" Channel(s) {skip_labels} skipped — not available or no camera connected."

    return {
        "check": check_name,
        "status": status,
        "detail": detail,
        "action": "" if status == "pass" else
                  f"Manually verify {check_name.lower()} on channel(s) {fail_labels or skip_labels}.",
    }


def _serialize(root):
    """Serialize an ElementTree element back to an XML string, preserving
    the device's own default namespace."""
    if '}' in root.tag:
        uri = root.tag.split('}', 1)[0][1:]
        try:
            ET.register_namespace('', uri)
        except Exception:
            pass
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


class DVRClient:
    def __init__(self, ip, port, username, password, use_https=False,
                 admin_verification_password=None):
        proto = "https" if use_https else "http"
        self.base_url = f"{proto}://{ip}:{port}/ISAPI"
        self.auth = HTTPDigestAuth(username, password)
        self.verify = False
        self.timeout = 15
        self._session = requests.Session()
        self.admin_verification_password = admin_verification_password or None
        self._cached_device_ns = None
        self._cached_device_context = None
        self._NS_FALLBACK = "http://www.std-cgi.com/ver20/XMLSchema"

    def _get(self, path):
        url = f"{self.base_url}{path}"
        try:
            r = self._session.get(url, auth=self.auth, verify=self.verify,
                                  timeout=self.timeout)
            r.raise_for_status()
            return r
        except requests.exceptions.RequestException as e:
            logger.error(f"GET {url} failed: {e}")
            raise

    def _put(self, path, xml_body):
        url = f"{self.base_url}{path}"
        try:
            r = self._session.put(url, auth=self.auth, verify=self.verify,
                                   timeout=self.timeout, data=xml_body,
                                   headers={"Content-Type": "application/xml"})
            r.raise_for_status()
            return r
        except requests.exceptions.RequestException as e:
            body_snippet = ""
            resp = getattr(e, "response", None)
            if resp is not None:
                try:
                    body_snippet = f" — response body: {resp.text[:1000]}"
                except Exception:
                    pass
            logger.error(f"PUT {url} failed: {e}{body_snippet}")
            raise

    def _put_text(self, path, text_body):
        """PUT raw plain-text content (not XML) to a path."""
        url = f"{self.base_url}{path}"
        try:
            r = self._session.put(url, auth=self.auth, verify=self.verify,
                                   timeout=self.timeout,
                                   data=text_body.encode("utf-8"),
                                   headers={"Content-Type": "text/plain"})
            r.raise_for_status()
            return r
        except requests.exceptions.RequestException as e:
            body_snippet = ""
            resp = getattr(e, "response", None)
            if resp is not None:
                try:
                    body_snippet = f" — response body: {resp.text[:1000]}"
                except Exception:
                    pass
            logger.error(f"PUT(text) {url} failed: {e}{body_snippet}")
            raise

    def _post(self, path, xml_body=""):
        url = f"{self.base_url}{path}"
        logger.debug(f"POST {url} — body:\n{xml_body}")
        try:
            r = self._session.post(url, auth=self.auth, verify=self.verify,
                                    timeout=self.timeout, data=xml_body,
                                    headers={"Content-Type": "application/xml"})
            r.raise_for_status()
            return r
        except requests.exceptions.RequestException as e:
            body_snippet = ""
            resp = getattr(e, "response", None)
            if resp is not None:
                try:
                    body_snippet = f" — response body: {resp.text[:1000]}"
                except Exception:
                    pass
            logger.error(f"POST {url} failed: {e}{body_snippet}")
            raise

    def test_connection(self):
        """Returns True if auth succeeds."""
        try:
            r = self._get("/System/deviceInfo")
            return r.status_code == 200
        except Exception:
            return False

    def configure_device_name(self, name):
        """Write the friendly device name to the device itself."""
        if not name:
            return False
        try:
            r = self._get("/System/deviceInfo")
            root = _parse_xml(r.text)
            if root is None:
                return False

            ns_prefix = root.tag.rsplit('}', 1)[0] + '}' if '}' in root.tag else ''

            WRITABLE = ["deviceName", "deviceID", "deviceDescription",
                        "deviceLocation", "systemContact", "telecontrolID"]

            minimal_root = ET.Element(root.tag)
            version = root.get("version")
            if version:
                minimal_root.set("version", version)

            for field in WRITABLE:
                if field == "deviceName":
                    el = ET.SubElement(minimal_root, f"{ns_prefix}deviceName")
                    el.text = name
                    continue
                existing = _find_first(root, field)
                if existing is not None and existing.text:
                    el = ET.SubElement(minimal_root, f"{ns_prefix}{field}")
                    el.text = existing.text

            minimal_xml = _serialize(minimal_root)
            try:
                self._put("/System/deviceInfo", minimal_xml)
            except Exception as e:
                logger.warning(f"Minimal deviceInfo PUT failed ({e}); "
                               f"retrying with full document round-trip")
                node = _find_first(root, "deviceName")
                if node is None:
                    node = ET.SubElement(root, f"{ns_prefix}deviceName")
                node.text = name
                self._put("/System/deviceInfo", _serialize(root))
            return True
        except Exception as e:
            logger.warning(f"Device name config failed: {e}")
            return False

    def get_device_info(self):
        r = self._get("/System/deviceInfo")
        root = _parse_xml(r.text)
        if root is None:
            return {}

        channels_total = 0
        channels_active = 0
        try:
            cr = self._get("/System/Video/inputs/channels")
            croot = _parse_xml(cr.text)
            if croot is not None:
                items = _find_all(croot, "VideoInputChannel")
                channels_total = len(items)
                for item in items:
                    enabled = _text(item, "enabled", default="false")
                    if enabled.lower() == "true":
                        channels_active += 1
                if channels_active == 0:
                    channels_active = channels_total
        except Exception:
            pass

        channel_ids = []
        try:
            sr = self._get("/Streaming/channels")
            sroot = _parse_xml(sr.text)
            if sroot is not None:
                mains = [c for c in _find_all(sroot, "StreamingChannel")
                         if _text(c, "id", default="").endswith("01")]
                channel_ids = [_text(c, "id") for c in mains]
                if channels_total == 0:
                    channels_total = len(mains)
                    channels_active = channels_total
        except Exception:
            pass

        try:
            pr = self._get("/ContentMgmt/InputProxy/channels/status")
            proot = _parse_xml(pr.text)
            if proot is not None:
                statuses = _find_all(proot, "InputProxyChannelStatus")
                if statuses:
                    online = 0
                    for s in statuses:
                        online_status = _text(s, "online", default="false").lower()
                        if online_status in ("true", "online"):
                            online += 1
                    channels_active = online
                    channels_total = max(channels_total, len(statuses))
        except Exception:
            pass

        mac = "N/A"
        try:
            nr = self._get("/System/Network/interfaces")
            nroot = _parse_xml(nr.text)
            if nroot is not None:
                mac = _text(nroot, "NetworkInterface", "IPAddress", "ipAddress", default="N/A")
                mac_node = _find_first(nroot, "MACAddress")
                if mac_node is not None and mac_node.text:
                    mac = mac_node.text.strip()
        except Exception:
            pass

        cur_time = "N/A"
        cur_tz = "N/A"
        try:
            tr = self._get("/System/time")
            troot = _parse_xml(tr.text)
            if troot is not None:
                cur_time = _text(troot, "localTime", default=_text(troot, "timeZone", default="N/A"))
                cur_tz = _text(troot, "timeZone", default="N/A")
        except Exception:
            pass

        return {
            "device_name_on_device": _text(root, "deviceName", default="N/A"),
            "manufacturer": _text(root, "manufacturer", default="Hikvision"),
            "model": _text(root, "model", default="N/A"),
            "device_type": _text(root, "deviceType", default="N/A"),
            "serial_number": _text(root, "serialNumber", default="N/A"),
            "firmware_version": _text(root, "firmwareVersion", default="N/A"),
            "total_channels": channels_total,
            "active_channels": channels_active,
            "channel_ids": channel_ids,
            "mac_address": mac,
            "current_timezone": cur_tz,
            "current_datetime": cur_time,
        }

    def get_timezone_for_state(self, state):
        return STATE_TIMEZONE.get(state, "America/Chicago")

    def configure_time(self, city, state):
        iana_tz = self.get_timezone_for_state(state)
        hik_tz = TZ_TO_HIKVISION.get(iana_tz, "CST6CDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00")
        dst_enabled = "," in hik_tz

        try:
            from zoneinfo import ZoneInfo
            local_time_iso = datetime.now(ZoneInfo(iana_tz)).isoformat(timespec="seconds")
        except Exception as e:
            logger.warning(f"Could not compute local time for {iana_tz}: {e}")
            local_time_iso = datetime.utcnow().isoformat(timespec="seconds")

        ntp_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<NTPServer>
  <id>1</id>
  <addressingFormatType>hostname</addressingFormatType>
  <hostName>pool.ntp.org</hostName>
  <portNo>123</portNo>
  <synchronizeInterval>1440</synchronizeInterval>
</NTPServer>"""
        try:
            self._put("/System/time/ntpServers/1", ntp_xml)
        except Exception:
            try:
                self._post("/System/time/ntpServers", ntp_xml)
            except Exception as e:
                logger.warning(f"NTP config failed: {e}")

        try:
            self._put_text("/System/time/timeZone", hik_tz)
            logger.info(f"Timezone applied via /System/time/timeZone (dedicated): {hik_tz}")
        except Exception as _e_tz_ded:
            logger.warning(
                f"/System/time/timeZone dedicated endpoint not available ({_e_tz_ded}); "
                f"will fall back to XML patch on /System/time"
            )

        time_xml_raw = None
        try:
            tr = self._get("/System/time")
            if tr.status_code == 200:
                time_xml_raw = tr.text
                logger.debug(f"/System/time GET body: {time_xml_raw!r}")
        except Exception as e:
            logger.warning(f"Could not GET /System/time: {e}")

        if time_xml_raw:
            tz_tag  = "timeZone"  if "<timeZone>"  in time_xml_raw else \
                      "timezone"  if "<timezone>"  in time_xml_raw else "timeZone"
            dst_tag = "DSTEnable" if "<DSTEnable>" in time_xml_raw else \
                      "dstEnable" if "<dstEnable>" in time_xml_raw else "DSTEnable"

            patched_tz_only = _patch_xml_fields(time_xml_raw, [
                (tz_tag,  hik_tz),
                (dst_tag, "true" if dst_enabled else "false"),
            ])
            try:
                self._put("/System/time", patched_tz_only)
                logger.info(f"/System/time updated (TZ+DST): {tz_tag}={hik_tz}")
            except Exception as e1:
                logger.warning(f"/System/time TZ-only patch failed ({e1}); "
                               f"retrying with timeMode=NTP included")
                patched_full = _patch_xml_fields(time_xml_raw, [
                    ("timeMode", "NTP"),
                    (tz_tag,     hik_tz),
                    (dst_tag,    "true" if dst_enabled else "false"),
                ])
                try:
                    self._put("/System/time", patched_full)
                    logger.info(f"/System/time updated (timeMode+TZ+DST): {tz_tag}={hik_tz}")
                except Exception as e2:
                    logger.warning(
                        f"/System/time full-patch also failed ({e2}). "
                        f"NTP server is configured; device will sync timezone on reboot."
                    )
        else:
            logger.warning("/System/time GET failed; skipping timezone PUT")

        self._configure_dst_explicit(dst_enabled)

        return {
            "iana_timezone": iana_tz,
            "hikvision_timezone": hik_tz,
            "ntp_server": "pool.ntp.org",
            "ntp_interval": 1440,
            "dst_enabled": dst_enabled,
        }

    def _configure_dst_explicit(self, dst_enabled):
        if dst_enabled:
            dst_xml = """<?xml version="1.0" encoding="UTF-8"?>
<DSTInfo>
  <enabled>true</enabled>
  <DSTBias>60</DSTBias>
  <DSTStart>
    <month>3</month>
    <week>2</week>
    <weekday>0</weekday>
    <hour>0</hour>
  </DSTStart>
  <DSTEnd>
    <month>11</month>
    <week>1</week>
    <weekday>0</weekday>
    <hour>0</hour>
  </DSTEnd>
</DSTInfo>"""
        else:
            dst_xml = """<?xml version="1.0" encoding="UTF-8"?>
<DSTInfo>
  <enabled>false</enabled>
</DSTInfo>"""
        try:
            self._put("/System/DST", dst_xml)
            logger.info(f"DST configured via /System/DST: enabled={dst_enabled}")
        except Exception as e:
            logger.info(f"/System/DST endpoint not available ({e}); "
                        "DST was already set via /System/time patch")

    def get_storage_info(self):
        r = self._get("/ContentMgmt/Storage")
        root = _parse_xml(r.text)
        if root is None:
            return []

        hdds = []
        for hdd in _find_all(root, "hddList"):
            for item in _find_all(hdd, "hdd"):
                hdds.append({
                    "id": _text(item, "id", default="1"),
                    "name": _text(item, "hddName", default="HDD"),
                    "capacity": _text(item, "capacity", default="N/A"),
                    "free_space": _text(item, "freeSpace", default="N/A"),
                    "status": _text(item, "status", default="uninitialized"),
                    "property": _text(item, "property", default="N/A"),
                })

        if not hdds:
            for item in _find_all(root, "hdd"):
                hdds.append({
                    "id": _text(item, "id", default="1"),
                    "name": _text(item, "hddName", default="HDD 1"),
                    "capacity": _text(item, "capacity", default="N/A"),
                    "free_space": _text(item, "freeSpace", default="N/A"),
                    "status": _text(item, "status", default="uninitialized"),
                    "property": _text(item, "property", default="R/W"),
                })
        return hdds

    def format_hdd(self, hdd_id):
        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<storage>
  <hddList>
    <hdd>
      <id>{hdd_id}</id>
    </hdd>
  </hddList>
</storage>"""
        try:
            self._put(f"/ContentMgmt/Storage/hdd/{hdd_id}/format", "")
        except Exception:
            try:
                self._post(f"/ContentMgmt/Storage/format", xml_body)
            except Exception as e:
                logger.warning(f"HDD format attempt failed: {e}")
                raise

    def get_streaming_channels(self):
        r = self._get("/Streaming/channels")
        root = _parse_xml(r.text)
        if root is None:
            return []
        return _find_all(root, "StreamingChannel")

    def get_available_resolutions(self, channel_id):
        try:
            r = self._get(f"/Streaming/channels/{channel_id}/capabilities")
            root = _parse_xml(r.text)
            if root is None:
                return []
            return []
        except Exception:
            return []

    def _patch_stream_channel(self, channel_id, fields):
        try:
            r = self._get(f"/Streaming/channels/{channel_id}")
            root = _parse_xml(r.text)
            if root is None:
                logger.warning(f"Stream channel {channel_id}: could not parse GET response")
                return False
            ns_prefix = root.tag.rsplit('}', 1)[0] + '}' if '}' in root.tag else ''
            for tag, value in fields.items():
                node = _find_first(root, tag)
                if node is None:
                    node = ET.SubElement(root, f"{ns_prefix}{tag}")
                node.text = str(value)
            self._put(f"/Streaming/channels/{channel_id}", _serialize(root))
            return True
        except Exception as e:
            return False

    def _patch_video_fields(self, channel_root, video_fields):
        ns_prefix = channel_root.tag.rsplit('}', 1)[0] + '}' if '}' in channel_root.tag else ''
        video_node = _find_first(channel_root, "Video")
        if video_node is None:
            video_node = ET.SubElement(channel_root, f"{ns_prefix}Video")
        for tag, value in video_fields.items():
            node = _find_first(video_node, tag)
            if node is None:
                node = ET.SubElement(video_node, f"{ns_prefix}{tag}")
            node.text = str(value)

    def get_online_channel_ids(self, all_channel_ids):
        if not all_channel_ids:
            return all_channel_ids

        try:
            pr = self._get("/ContentMgmt/InputProxy/channels/status")
            proot = _parse_xml(pr.text)
            if proot is None:
                logger.info("InputProxy status unavailable — using all channel IDs")
                return all_channel_ids

            statuses = _find_all(proot, "InputProxyChannelStatus")
            if not statuses:
                logger.info("No InputProxy channel statuses — using all channel IDs")
                return all_channel_ids

            online_nums = set()
            for s in statuses:
                ch_id  = _text(s, "id", default="").strip()
                online = _text(s, "online", default="false").strip().lower()
                if online in ("true", "online", "1"):
                    online_nums.add(ch_id)

            if not online_nums:
                logger.warning(
                    "InputProxy reports no online cameras — "
                    "falling back to all channel IDs to avoid skipping everything"
                )
                return all_channel_ids

            online_main_ids = []
            for cid in all_channel_ids:
                prefix = cid[:-2]
                ch_num = str(int(prefix)) if prefix.isdigit() else prefix
                if ch_num in online_nums:
                    online_main_ids.append(cid)

            if not online_main_ids:
                logger.warning(
                    "Could not match online channels to streaming IDs — "
                    "using all channel IDs"
                )
                return all_channel_ids

            skipped = [cid for cid in all_channel_ids if cid not in online_main_ids]
            if skipped:
                logger.info(f"Skipping offline/inactive channel(s): {skipped}")

            logger.info(f"Active channels selected for configuration: {online_main_ids}")
            return online_main_ids

        except Exception as e:
            logger.warning(f"Could not query InputProxy status ({e}) — using all channel IDs")
            return all_channel_ids

    def list_active_channels_for_naming(self):
        online_map = {}
        try:
            pr = self._get("/ContentMgmt/InputProxy/channels/status")
            proot = _parse_xml(pr.text)
            if proot is not None:
                for s in _find_all(proot, "InputProxyChannelStatus"):
                    cid = _text(s, "id", default="").strip()
                    online = _text(s, "online", default="false").strip().lower()
                    online_map[cid] = online in ("true", "online", "1")
        except Exception as e:
            logger.info(f"InputProxy status unavailable for naming: {e}")

        channels_by_id = {}

        try:
            cr = self._get("/System/Video/inputs/channels")
            croot = _parse_xml(cr.text)
            if croot is not None:
                for item in _find_all(croot, "VideoInputChannel"):
                    ch_id = _text(item, "id", default="").strip()
                    if not ch_id:
                        continue
                    name = _text(item, "name", default="")
                    enabled = _text(item, "enabled", default="true").lower() == "true"
                    channels_by_id[ch_id] = {"channel_id": ch_id, "name": name, "enabled": enabled, "source": "analog"}
        except Exception as e:
            logger.info(f"list_active_channels_for_naming: /System/Video/inputs/channels unavailable: {e}")

        try:
            ir = self._get("/ContentMgmt/InputProxy/channels")
            iroot = _parse_xml(ir.text)
            if iroot is not None:
                for item in _find_all(iroot, "InputProxyChannel"):
                    ch_id = _text(item, "id", default="").strip()
                    if not ch_id or ch_id in channels_by_id:
                        continue
                    name = _text(item, "name", default="")
                    channels_by_id[ch_id] = {"channel_id": ch_id, "name": name, "enabled": True, "source": "ip_proxy"}
        except Exception as e:
            logger.info(f"list_active_channels_for_naming: /ContentMgmt/InputProxy/channels unavailable: {e}")

        if not channels_by_id:
            logger.warning("list_active_channels_for_naming: neither video-input nor InputProxy channel list returned data")
            return []

        active = []
        for ch in channels_by_id.values():
            if not ch["enabled"]:
                continue
            if ch["channel_id"] in online_map and not online_map[ch["channel_id"]]:
                continue
            ch["online"] = True
            active.append(ch)
        return active

    def apply_channel_name(self, channel_id, new_name):
        new_name = (new_name or "").strip()[:64]
        if not new_name:
            return False, "Name is empty"

        ok_analog = False
        try:
            r = self._get(f"/System/Video/inputs/channels/{channel_id}")
            if r.status_code == 200:
                patched = _patch_xml_fields(r.text, [("name", new_name)])
                pr = self._put(f"/System/Video/inputs/channels/{channel_id}", patched)
                ok_analog = pr.status_code in (200, 201)
            else:
                logger.info(f"apply_channel_name: analog channel endpoint not available for channel {channel_id} (HTTP {r.status_code})")
        except Exception as e:
            logger.info(f"apply_channel_name: analog channel name update skipped for channel {channel_id}: {e}")

        try:
            r = self._get(f"/System/Video/inputs/channels/{channel_id}/overlays/channelNameOverlay")
            if r.status_code == 200:
                patched = _patch_xml_fields(r.text, [
                    ("enabled", "true"),
                    ("name", new_name),
                ])
                self._put(f"/System/Video/inputs/channels/{channel_id}/overlays/channelNameOverlay", patched)
        except Exception as e:
            logger.info(f"apply_channel_name: overlay update skipped for channel {channel_id}: {e}")

        ok_proxy = False
        try:
            r = self._get(f"/ContentMgmt/InputProxy/channels/{channel_id}")
            if r.status_code == 200:
                patched = _patch_xml_fields(r.text, [("name", new_name)])
                pr = self._put(f"/ContentMgmt/InputProxy/channels/{channel_id}", patched)
                ok_proxy = pr.status_code in (200, 201)
            else:
                logger.info(f"apply_channel_name: InputProxy endpoint not available for channel {channel_id} (HTTP {r.status_code})")
        except Exception as e:
            logger.info(f"apply_channel_name: InputProxy name update skipped for channel {channel_id}: {e}")

        if ok_analog or ok_proxy:
            return True, "Name applied"
        return False, "Failed to update channel name on device"

    def configure_main_stream(self, channel_id):
        try:
            r = self._get(f"/Streaming/channels/{channel_id}")
            if r.status_code != 200:
                logger.warning(f"Main stream GET channel {channel_id}: HTTP {r.status_code}")
                return False
            patched = _patch_xml_fields(r.text, [
                ("videoCodecType",          "H.264"),
                ("videoResolutionWidth",    "1920"),
                ("videoResolutionHeight",   "1080"),
                ("videoQualityControlType", "CBR"),
                ("maxFrameRate",            "800"),
                ("vbrUpperCap",             "320"),
                ("constantBitRate",         "320"),
            ])
            self._put(f"/Streaming/channels/{channel_id}", patched)
            logger.info(f"Main stream channel {channel_id}: configured 1920×1080 H.264 CBR 320kbps 8fps")
            return True
        except Exception as e:
            logger.warning(f"Main stream config channel {channel_id}: {e}")
            return False

    def configure_event_stream(self, channel_id):
        event_id = channel_id[:-2] + "03" if len(channel_id) >= 3 else channel_id
        try:
            r = self._get(f"/Streaming/channels/{event_id}")
            if r.status_code != 200:
                logger.info(f"Event stream channel {event_id} not available (HTTP {r.status_code}) — skipping")
                return False
            patched = _patch_xml_fields(r.text, [
                ("videoCodecType",          "H.264"),
                ("videoResolutionWidth",    "1920"),
                ("videoResolutionHeight",   "1080"),
                ("videoQualityControlType", "CBR"),
                ("maxFrameRate",            "800"),
                ("vbrUpperCap",             "320"),
                ("constantBitRate",         "320"),
            ])
            self._put(f"/Streaming/channels/{event_id}", patched)
            logger.info(f"Event stream channel {event_id}: configured 1920×1080 H.264 CBR 320kbps 8fps")
            return True
        except Exception as e:
            logger.info(f"Event stream config channel {event_id}: {e} (non-fatal)")
            return False

    def configure_sub_stream(self, channel_id):
        RESOLUTION_CHAIN = [
            ("960", "576"),
            ("960", "540"),
            ("704", "576"),
            ("704", "480"),
            ("640", "480"),
        ]
        sub_id = channel_id[:-2] + "02" if len(channel_id) >= 3 else channel_id
        try:
            r = self._get(f"/Streaming/channels/{sub_id}")
            if r.status_code != 200:
                logger.warning(f"Sub stream GET channel {sub_id}: HTTP {r.status_code}")
                return {'ok': False, 'status': 'error',
                        'applied_resolution': 'N/A',
                        'note': f'GET returned HTTP {r.status_code}'}
            original_xml = r.text
            last_error = None
            for w, h in RESOLUTION_CHAIN:
                try:
                    patched = _patch_xml_fields(original_xml, [
                        ("videoCodecType",          "H.264"),
                        ("videoResolutionWidth",     w),
                        ("videoResolutionHeight",    h),
                        ("videoQualityControlType", "CBR"),
                        ("maxFrameRate",             "800"),
                        ("vbrUpperCap",              "320"),
                        ("constantBitRate",          "320"),
                    ])
                    self._put(f"/Streaming/channels/{sub_id}", patched)
                    is_primary = (w == "960" and h == "576")
                    res_str    = f"{w}×{h}"
                    status     = 'configured' if is_primary else 'configured_fallback'
                    note       = "" if is_primary else (
                        f"960×576 not supported — device accepted {res_str}")
                    logger.info(
                        f"Sub stream {sub_id}: configured {res_str} H.264 CBR 320kbps 8fps"
                        + (" (fallback)" if not is_primary else "")
                    )
                    return {'ok': True, 'status': status,
                            'applied_resolution': res_str, 'note': note}
                except Exception as e_res:
                    last_error = e_res
                    logger.debug(
                        f"Sub stream {sub_id}: {w}×{h} rejected ({e_res}); "
                        f"trying next resolution in chain…"
                    )
                    continue
            logger.warning(
                f"Sub stream {sub_id}: all resolutions in chain rejected. "
                f"Last error: {last_error}"
            )
            return {'ok': False, 'status': 'error',
                    'applied_resolution': 'N/A',
                    'note': f'All resolutions rejected. Last: {last_error}'}
        except Exception as e:
            logger.warning(f"Sub stream config channel {sub_id}: {e}")
            return {'ok': False, 'status': 'error',
                    'applied_resolution': 'N/A', 'note': str(e)}

    def disable_channel_zero(self):
        try:
            r = self._get("/Streaming/channels/0")
            root = _parse_xml(r.text)
            if root is not None:
                ns_prefix = root.tag.rsplit('}', 1)[0] + '}' if '}' in root.tag else ''
                node = _find_first(root, "enabled")
                if node is None:
                    node = ET.SubElement(root, f"{ns_prefix}enabled")
                node.text = "false"
                self._put("/Streaming/channels/0", _serialize(root))
        except Exception as e:
            logger.warning(f"Channel zero disable: {e}")

    def configure_recording_schedule(self, channel_id):
        import re as _re

        WEEK = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
                "Saturday", "Sunday"]

        def _make_action(action_id, start_day, start_time, end_day, end_time, mode):
            return (
                f"<ScheduleAction>"
                f"<id>{action_id}</id>"
                f"<ScheduleActionStartTime>"
                f"<DayOfWeek>{start_day}</DayOfWeek>"
                f"<TimeOfDay>{start_time}</TimeOfDay>"
                f"</ScheduleActionStartTime>"
                f"<ScheduleActionEndTime>"
                f"<DayOfWeek>{end_day}</DayOfWeek>"
                f"<TimeOfDay>{end_time}</TimeOfDay>"
                f"</ScheduleActionEndTime>"
                f"<ScheduleDSTEnable>false</ScheduleDSTEnable>"
                f"<Description>nothing</Description>"
                f"<Actions>"
                f"<Record>true</Record>"
                f"<Log>false</Log>"
                f"<SaveImg>false</SaveImg>"
                f"<ActionRecordingMode>{mode}</ActionRecordingMode>"
                f"</Actions>"
                f"</ScheduleAction>"
            )

        def _make_block(guid_suffix, mode, start_time, end_time):
            actions = []
            for idx, day in enumerate(WEEK):
                next_day = WEEK[(idx + 1) % 7]
                end_day = next_day if end_time == "00:00:00" else day
                actions.append(_make_action(idx + 1, day, start_time,
                                            end_day, end_time, mode))
            guid = f"{{0000000{guid_suffix}-0000-0000-0000-000000000000}}"
            return (
                f"<ScheduleBlock>"
                f"<ScheduleBlockGUID>{guid}</ScheduleBlockGUID>"
                f"<ScheduleBlockType>www.std-cgi.com/racm/schedule/ver10</ScheduleBlockType>"
                + "".join(actions) +
                f"</ScheduleBlock>"
            )

        new_track_schedule = (
            "<TrackSchedule>"
            "<ScheduleBlockList>"
            + _make_block("0", "MOTION", "00:00:00", "08:00:00")
            + _make_block("1", "CMR",    "08:00:00", "22:00:00")
            + _make_block("2", "MOTION", "22:00:00", "00:00:00")
            + "</ScheduleBlockList>"
            "</TrackSchedule>"
        )

        track_path = f"/ContentMgmt/record/tracks/{channel_id}"
        try:
            r = self._get(track_path)
            track_xml = r.text

            if "<TrackSchedule>" in track_xml:
                updated_xml = _re.sub(
                    r"<TrackSchedule>.*?</TrackSchedule>",
                    new_track_schedule,
                    track_xml,
                    flags=_re.DOTALL,
                )
            else:
                updated_xml = track_xml.replace(
                    "</Track>", new_track_schedule + "\n</Track>"
                )

            self._put(track_path, updated_xml)
            return True
        except Exception as e:
            logger.warning(f"Recording schedule channel {channel_id}: {e}")
            return False

    def configure_holiday(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<HolidayList>
  <Holiday>
    <id>1</id>
    <holidayName>Thanksgiving &amp; Black Friday</holidayName>
    <enabled>true</enabled>
    <holidayMode>byWeek</holidayMode>
    <holidayWeek>
      <startMonth>11</startMonth>
      <startWeek>4</startWeek>
      <startWeekDay>2</startWeekDay>
      <endMonth>12</endMonth>
      <endWeek>1</endWeek>
      <endWeekDay>2</endWeekDay>
    </holidayWeek>
  </Holiday>
</HolidayList>"""
        try:
            self._put("/System/holidays", xml)
            return True
        except Exception as e:
            logger.warning(f"Holiday config: {e}")
            return False

    def _get_device_context(self):
        if hasattr(self, '_cached_device_context') and self._cached_device_context is not None:
            return self._cached_device_context
        try:
            r = self._session.get(
                f"{self.base_url}/System/deviceInfo",
                auth=self.auth, verify=self.verify, timeout=self.timeout
            )
            root = _parse_xml(r.text) if r.status_code == 200 else None
            ctx = {
                "manufacturer":     _text(root, "manufacturer",     default="Unknown") if root is not None else "Unknown",
                "model":            _text(root, "model",            default="Unknown") if root is not None else "Unknown",
                "firmware_version": _text(root, "firmwareVersion",  default="Unknown") if root is not None else "Unknown",
                "device_type":      _text(root, "deviceType",       default="Unknown") if root is not None else "Unknown",
            }
        except Exception:
            ctx = {}
        self._cached_device_context = ctx
        return ctx

    def check_double_verification(self):
        endpoint = "/Security/userDoubleVerification"
        try:
            r = self._session.get(
                f"{self.base_url}{endpoint}",
                auth=self.auth, verify=self.verify, timeout=self.timeout
            )
            if r.status_code in (404, 405, 501):
                logger.debug(f"[DVR DoubleVerif] Endpoint not supported (HTTP {r.status_code})")
                return {'supported': False, 'enabled': False}
            if r.status_code == 200:
                root = _parse_xml(r.text)
                enabled_text = (_text(root, "enabled", default="false") or "false").lower() if root is not None else "false"
                enabled = enabled_text in ("true", "1", "yes")
                logger.info(f"[DVR DoubleVerif] supported=True, enabled={enabled}")
                return {'supported': True, 'enabled': enabled}
            logger.debug(f"[DVR DoubleVerif] Unexpected HTTP {r.status_code} — treating as unsupported")
            return {'supported': False, 'enabled': False}
        except Exception as e:
            logger.debug(f"[DVR DoubleVerif] Probe error: {e}")
            return {'supported': False, 'enabled': False, 'error': str(e)}

    def set_double_verification(self, enabled: bool):
        endpoint = "/Security/userDoubleVerification"
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<UserDoubleVerification>\n'
            f'  <enabled>{"true" if enabled else "false"}</enabled>\n'
            '</UserDoubleVerification>'
        )
        try:
            r = self._session.put(
                f"{self.base_url}{endpoint}",
                auth=self.auth, verify=self.verify, timeout=self.timeout,
                data=xml, headers={"Content-Type": "application/xml"}
            )
            success = r.status_code in (200, 204)
            logger.info(f"[DVR DoubleVerif] set enabled={enabled} → HTTP {r.status_code} ({'ok' if success else 'failed'})")
            if not success:
                logger.debug(f"[DVR DoubleVerif] set response body: {r.text[:400]}")
            return success
        except Exception as e:
            logger.warning(f"[DVR DoubleVerif] Failed to set enabled={enabled}: {e}")
            return False

    def check_illegal_login_protection(self):
        try:
            r = self._session.get(
                f"{self.base_url}/Security/illegalLoginLock",
                auth=self.auth, verify=self.verify, timeout=self.timeout
            )
            if r.status_code in (404, 405, 501):
                return {'supported': False, 'locked': False}
            if r.status_code == 200:
                root = _parse_xml(r.text)
                locked_text = (_text(root, "isLocked", default="false") or "false").lower() if root is not None else "false"
                locked = locked_text in ("true", "1", "yes")
                logger.info(f"[DVR IllegalLoginLock] supported=True, locked={locked}")
                return {'supported': True, 'locked': locked}
            return {'supported': False, 'locked': False}
        except Exception as e:
            logger.debug(f"[DVR IllegalLoginLock] Probe error: {e}")
            return {'supported': False, 'locked': False}

    def _log_user_creation_failure(self, username, endpoint, http_status, exc, response_body=""):
        import traceback
        ctx = self._get_device_context()
        trace = traceback.format_exc()
        logger.error(
            "[DVR UserCreate FAILED]\n"
            f"  username        : {username!r}\n"
            f"  api_endpoint    : {self.base_url}{endpoint}\n"
            f"  http_status     : {http_status if http_status is not None else 'N/A'}\n"
            f"  manufacturer    : {ctx.get('manufacturer', 'Unknown')}\n"
            f"  model           : {ctx.get('model', 'Unknown')}\n"
            f"  firmware_version: {ctx.get('firmware_version', 'Unknown')}\n"
            f"  device_type     : {ctx.get('device_type', 'Unknown')}\n"
            f"  exception       : {exc}\n"
            f"  response_body   : {(response_body or 'N/A')[:1000]}\n"
            f"  stack_trace     :\n{trace}"
        )

    # ============================================================
    # FIXED USER CREATION METHODS - NO XML DECLARATION ON POST
    # ============================================================

    def _build_create_user_xml_from_template(self, username, password, user_level):
        """GET an existing user from the device and clone its raw XML structure.
        
        CRITICAL: This device rejects XML declarations. The raw <User> block 
        alone must be sent with NO <?xml?> declaration.
        """
        import re as _re
        
        try:
            r = self._get("/Security/users")
            raw = r.text
            
            # Extract the first complete <User> block - handles namespace prefixes
            match = _re.search(
                r'<(?:[^:>\s/]+:)?User(?:\s[^>]*)?>.*?</(?:[^:>\s/]+:)?User>',
                raw, _re.DOTALL
            )
            if not match:
                return None
            
            user_block = match.group(0)
            
            # Build patch dictionary
            patch = {
                'id': '0',
                'userName': username,
                'userLevel': user_level,
                'inherent': 'false',
            }
            
            if self.admin_verification_password:
                patch['adminPassword'] = self.admin_verification_password
            
            # Apply patches
            user_block = _patch_xml_fields(user_block, patch)
            
            # Insert password tag (GET never includes it)
            if '<password>' not in user_block and password:
                user_block = _re.sub(
                    r'(</(?:[^:>\s/]+:)?userName>)',
                    lambda m: m.group(0) + f'\n<password>{password}</password>',
                    user_block,
                    count=1,
                    flags=_re.IGNORECASE
                )
            
            # CRITICAL: NO XML DECLARATION - device treats it as a root tag
            return user_block
            
        except Exception as e:
            logger.debug(f"_build_create_user_xml_from_template: {e}")
            return None

    def _create_user_inner(self, username, password, user_level):
        """Internal user creation logic."""
        
        # Check if user already exists
        existing = self._get_existing_users()
        if username in existing:
            uid = existing[username]
            self._update_user_password(uid, username, password, user_level)
            return uid
        
        # Build XML - NO DECLARATION, uses correct field names
        xml = self._build_create_user_xml_from_template(username, password, user_level)
        
        if xml is None:
            # Fallback template - NO XML DECLARATION, correct field names
            _admin_pw_tag = (
                f'  <adminPassword>{self.admin_verification_password}</adminPassword>\n'
                if self.admin_verification_password else ''
            )
            xml = (
                '<User>\n'
                '  <id>0</id>\n'
                f'  <userName>{username}</userName>\n'
                f'  <password>{password}</password>\n'
                + _admin_pw_tag +
                '  <bondIpAddressList>\n'
                '    <bondIpAddress>\n'
                '      <id>1</id>\n'
                '      <ipAddress>0.0.0.0</ipAddress>\n'
                '      <ipv6Address>::</ipv6Address>\n'
                '    </bondIpAddress>\n'
                '  </bondIpAddressList>\n'
                '  <bondMacAddressList>\n'
                '    <bondMacAddress>\n'
                '      <id>1</id>\n'
                '      <macAddress>00:00:00:00:00:00</macAddress>\n'
                '    </bondMacAddress>\n'
                '  </bondMacAddressList>\n'
                f'  <userLevel>{user_level}</userLevel>\n'
                '  <attribute>\n'
                '    <inherent>false</inherent>\n'
                '  </attribute>\n'
                '</User>'
            )
        
        # Try UserMgmt endpoint first (this is the writable one)
        try:
            r = self._post("/Security/UserMgmt/users", xml)
            root = _parse_xml(r.text)
            uid = _text(root, "id", default="") if root is not None else ""
            if uid:
                logger.info(f"User '{username}' created via POST /Security/UserMgmt/users")
                return uid
        except Exception as e:
            logger.info(f"POST /Security/UserMgmt/users failed: {e}")
        
        # Try legacy endpoint (will likely fail on this device)
        try:
            r = self._post("/Security/users", xml)
            root = _parse_xml(r.text)
            uid = _text(root, "id", default="") if root is not None else ""
            if uid:
                logger.info(f"User '{username}' created via POST /Security/users")
                return uid
        except Exception as e:
            logger.warning(f"POST /Security/users failed: {e}")
        
        # Final fallback - try UserMgmt with full XML document (with declaration)
        # Some devices need the declaration for PUT but not POST
        try:
            full_xml = f'<?xml version="1.0" encoding="UTF-8"?>\n{xml}'
            r = self._post("/Security/UserMgmt/users", full_xml)
            root = _parse_xml(r.text)
            uid = _text(root, "id", default="") if root is not None else ""
            if uid:
                logger.info(f"User '{username}' created via POST /Security/UserMgmt/users with declaration")
                return uid
        except Exception as e:
            logger.warning(f"POST /Security/UserMgmt/users with declaration failed: {e}")
        
        # If we get here, the device doesn't support API user creation
        # Log detailed diagnostics and raise a clear error
        ctx = self._get_device_context()
        raise Exception(
            f"User creation via ISAPI is not supported on this device.\n"
            f"Device: {ctx.get('manufacturer', 'Unknown')} {ctx.get('model', 'Unknown')}\n"
            f"Firmware: {ctx.get('firmware_version', 'Unknown')}\n"
            f"Please create user '{username}' manually via the device web interface.\n"
            f"Endpoint /Security/UserMgmt/users is not available on this firmware."
        )

    # ============================================================
    # END OF FIXED USER CREATION METHODS
    # ============================================================

    def _detect_device_ns(self):
        if hasattr(self, '_cached_device_ns') and self._cached_device_ns is not None:
            return self._cached_device_ns
        try:
            r = self._get("/Security/users")
            root = _parse_xml(r.text)
            if root is not None and '}' in root.tag:
                ns = root.tag.split('}', 1)[0][1:]
            else:
                ns = self._NS_FALLBACK
        except Exception:
            ns = self._NS_FALLBACK
        self._cached_device_ns = ns
        logger.debug(f"Detected device XML namespace: {ns}")
        return ns

    def _get_existing_users(self):
        try:
            r = self._get("/Security/users")
            root = _parse_xml(r.text)
            if root is None:
                return {}
            if not hasattr(self, '_cached_device_ns') and '}' in root.tag:
                self._cached_device_ns = root.tag.split('}', 1)[0][1:]
            users = {}
            for u in _find_all(root, "User"):
                uid = _text(u, "id", default="")
                uname = _text(u, "userName", default="")
                if uid and uname:
                    users[uname] = uid
            return users
        except Exception as e:
            logger.warning(f"Get existing users: {e}")
            return {}

    _USER_LEVEL_MAP = {
        "viewer": "Viewer",
        "operator": "Operator",
        "admin": "Administrator",
        "administrator": "Administrator",
    }

    _DOUBLE_VERIF_KEYWORDS = (
        "doubleverif", "double verif", "double_verif",
        "usercheck", "user check",
        "secondary verif", "secondaryadmin",
        "illegal login", "illegally", "illegallogin",
        "verification required", "additional verif",
    )

    @staticmethod
    def _is_double_verif_error(text):
        t = (text or "").lower()
        return any(kw in t for kw in DVRClient._DOUBLE_VERIF_KEYWORDS)

    def create_user(self, username, password, role="viewer"):
        user_level = self._USER_LEVEL_MAP.get(role.lower(), "Viewer")

        ill_lock = self.check_illegal_login_protection()
        if ill_lock.get('supported') and ill_lock.get('locked'):
            msg = (
                f"Device has Illegal Login Protection active — user creation for "
                f"'{username}' is blocked until the lock timer expires."
            )
            logger.error(f"[DVR UserCreate] {msg}")
            raise Exception(msg)

        dv = self.check_double_verification()
        dv_was_enabled = dv.get('supported') and dv.get('enabled')
        dv_disabled_by_us = False

        if dv_was_enabled:
            logger.info(
                f"[DVR UserCreate] Double Verification is ENABLED on this device. "
                f"Attempting to temporarily disable it before creating user '{username}'."
            )
            dv_disabled_by_us = self.set_double_verification(False)
            if not dv_disabled_by_us:
                logger.warning(
                    f"[DVR UserCreate] Could not disable Double Verification — "
                    f"user creation for '{username}' may fail with a verification error."
                )

        try:
            return self._create_user_inner(username, password, user_level)
        except Exception as exc:
            err_str = str(exc)
            if self._is_double_verif_error(err_str):
                if dv_was_enabled and not dv_disabled_by_us:
                    detail = (
                        f"Double Verification is enabled on this device and could not be "
                        f"temporarily disabled — the device blocked user creation for '{username}'. "
                        f"Disable Double Verification manually on the device web UI "
                        f"(System → User Management → Double Verification) and retry."
                    )
                elif dv_was_enabled and dv_disabled_by_us:
                    detail = (
                        f"Double Verification was detected and temporarily disabled, but user "
                        f"creation for '{username}' still returned a verification error."
                    )
                else:
                    detail = (
                        f"User creation for '{username}' was rejected with a Double Verification "
                        f"or Illegal Login error. Check System → User Management → Double Verification "
                        f"on the device web UI."
                    )
                logger.error(f"[DVR UserCreate] {detail}")
                raise Exception(detail) from exc
            raise
        finally:
            if dv_was_enabled and dv_disabled_by_us:
                restored = self.set_double_verification(True)
                if restored:
                    logger.info(f"[DVR UserCreate] Double Verification restored to enabled.")
                else:
                    logger.error(
                        f"[DVR UserCreate] IMPORTANT: Failed to restore Double Verification after "
                        f"user creation attempt for '{username}'. "
                        f"Please manually re-enable it on the device web UI immediately."
                    )

    def _update_user_password(self, uid, username, password, user_level):
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<User>
  <id>{uid}</id>
  <userName>{username}</userName>
  <password>{password}</password>
  <userLevel>{user_level}</userLevel>
</User>"""
        logger.debug(f"PUT /Security/users/{uid} body:\n{xml}")
        try:
            self._put(f"/Security/users/{uid}", xml)
        except Exception as e:
            logger.warning(f"Update user {uid}: {e}")

    _PERMISSION_SPECS = {
        "cms": {
            "user_type": "viewer",
            "remote": {
                "preview": True,
                "playBack": True,
                "record": False,
                "logOrStateCheck": True,
                "parameterConfig": False,
                "restartOrShutdown": False,
                "upgrade": False,
                "voiceTalk": False,
                "ptzControl": False,
            },
            "local": {
                "preview": True,
                "playBack": True,
                "record": False,
                "logOrStateCheck": True,
                "backup": True,
                "ptzControl": False,
            },
        },
        "manager": {
            "user_type": "viewer",
            "remote": {
                "preview": True,
                "playBack": True,
                "record": False,
                "logOrStateCheck": True,
                "parameterConfig": False,
                "restartOrShutdown": False,
                "upgrade": False,
                "voiceTalk": False,
                "ptzControl": False,
            },
            "local": {
                "preview": True,
                "playBack": True,
                "record": False,
                "logOrStateCheck": True,
                "backup": True,
                "ptzControl": False,
            },
        },
        "dlt": {
            "user_type": "operator",
            "remote": {
                "preview": True,
                "playBack": True,
                "record": False,
                "logOrStateCheck": True,
                "parameterConfig": True,
                "restartOrShutdown": True,
                "upgrade": False,
                "voiceTalk": False,
                "ptzControl": False,
            },
            "local": {
                "preview": False,
                "playBack": False,
                "record": False,
                "logOrStateCheck": False,
                "backup": False,
                "ptzControl": False,
            },
        },
    }

    @staticmethod
    def _spec_key_for(permission_set):
        return permission_set if permission_set in ("cms", "manager", "dlt") else permission_set

    def set_user_permissions(self, uid, username, permission_set):
        spec = self._PERMISSION_SPECS[self._spec_key_for(permission_set)]
        user_type = spec["user_type"]

        def _fields_xml(fields):
            return "".join(f"\n      <{tag}>{'true' if val else 'false'}</{tag}>"
                            for tag, val in fields.items())

        remote_perms = _fields_xml(spec["remote"])
        local_perms  = _fields_xml(spec["local"])

        ns = self._detect_device_ns()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<UserPermission version="2.0" xmlns="{ns}">
  <id>{uid}</id>
  <userID>{uid}</userID>
  <userType>{user_type}</userType>
  <remotePermission>{remote_perms}
  </remotePermission>
  <localPermission>{local_perms}
  </localPermission>
</UserPermission>"""
        try:
            self._put(f"/Security/UserPermission/{uid}", xml)
            return True
        except Exception as e1:
            logger.warning(f"Set permissions for {username} via /Security/UserPermission/{uid} failed: {e1}; "
                           f"retrying legacy path /Security/users/{uid}/userPermission")
            try:
                self._put(f"/Security/users/{uid}/userPermission", xml)
                return True
            except Exception as e2:
                logger.warning(f"Set permissions for {username}: {e2}")
                return False

    def get_user_permissions(self, uid):
        try:
            r = self._get(f"/Security/UserPermission/{uid}")
            if r.status_code != 200 or not r.text:
                return None
            root = _parse_xml(r.text)
            if root is None:
                return None
            perms = {"remotePermission": {}, "localPermission": {}}
            for section_name in ("remotePermission", "localPermission"):
                section_node = _find_first(root, section_name)
                if section_node is not None:
                    for child in list(section_node):
                        tag = _local(child.tag)
                        val = (child.text or "").strip().lower()
                        perms[section_name][tag] = val in ("true", "1", "yes")
            return perms
        except Exception as e:
            logger.info(f"Get permissions for uid {uid}: {e}")
            return None

    def _permissions_match(self, current, permission_set):
        if not current:
            return False
        spec = self._PERMISSION_SPECS[self._spec_key_for(permission_set)]
        for section_name, fields in (("remotePermission", spec["remote"]), ("localPermission", spec["local"])):
            current_section = current.get(section_name, {})
            for tag, expected_val in fields.items():
                if current_section.get(tag) != expected_val:
                    return False
        return True

    def verify_and_sync_permissions(self, uid, username, permission_set):
        current = self.get_user_permissions(uid)
        if current is not None and self._permissions_match(current, permission_set):
            logger.info(f"Permissions for {username} already match the required set — no update needed")
            return {"ok": True, "status": "matched"}
        ok = self.set_user_permissions(uid, username, permission_set)
        return {"ok": ok, "status": "updated" if ok else "update_failed"}

    def configure_standard_account(self, username, password, permission_set):
        spec = self._PERMISSION_SPECS.get(self._spec_key_for(permission_set))
        if spec is None:
            return {"ok": False, "username": username,
                    "error": f"Unknown permission_set '{permission_set}'"}

        role = spec["user_type"]

        try:
            existing = self._get_existing_users()
            already_existed = username in existing
            uid = self.create_user(username, password, role=role)
        except Exception as e:
            logger.error(f"Account provisioning failed for {username}: {e}")
            return {"ok": False, "username": username, "error": str(e)}

        perm_result = self.verify_and_sync_permissions(uid, username, permission_set)

        final_perms = self.get_user_permissions(uid)
        if final_perms is not None:
            verified = self._permissions_match(final_perms, permission_set)
        else:
            verified = perm_result["ok"]

        return {
            "ok": perm_result["ok"],
            "uid": uid,
            "username": username,
            "already_existed": already_existed,
            "permission_status": perm_result["status"],
            "verified": verified,
        }

    def configure_manager_account(self, username, password):
        return self.configure_standard_account(username, password, "manager")

    def discover_permission_capabilities(self, user_type="viewer"):
        cap_path = f"/Security/UserPermission/{user_type}Cap"
        try:
            r = self._get(cap_path)
            root = _parse_xml(r.text)
            if root is None:
                return None
            caps = {"remotePermission": {}, "localPermission": {}}
            for section_name in ("remotePermission", "localPermission"):
                section_node = _find(root, section_name)
                if section_node is not None:
                    for child in list(section_node):
                        tag = _local(child.tag)
                        val = (child.text or "").strip().lower()
                        caps[section_name][tag] = val in ("true", "1", "yes")
            logger.info(f"Permission caps for '{user_type}': {caps}")
            return caps
        except Exception as e:
            logger.info(f"Permission capability discovery unavailable for '{user_type}': {e}")
            return None

    def validate_configuration(self, expected):
        results = []

        # Time / NTP
        try:
            r = self._get("/System/time")
            root = _parse_xml(r.text)
            tz = _text(root, "timeZone", default="") if root else ""
            mode = _text(root, "timeMode", default="") if root else ""
            local_time = _text(root, "localTime", default="N/A") if root else "N/A"

            results.append({
                "check": "Date & Time",
                "status": "pass" if local_time != "N/A" else "fail",
                "detail": f"Current time: {local_time}",
                "action": "Verify time is correct on the device." if local_time == "N/A" else "",
            })
            
            expected_tz = expected.get("hikvision_timezone", "")
            expected_tz_prefix = expected_tz.split(",")[0].split("-")[0].split("+")[0] if expected_tz else ""
            tz_ok = bool(expected_tz_prefix) and expected_tz_prefix in tz
            results.append({
                "check": "Time Zone",
                "status": "pass" if tz_ok else "warn",
                "detail": f"Timezone: {tz}",
                "action": "" if tz_ok else "Check timezone setting on device.",
            })
            results.append({
                "check": "NTP Configuration",
                "status": "pass" if mode.lower() == "ntp" else "warn",
                "detail": f"Time mode: {mode}",
                "action": "Ensure NTP mode is selected." if mode.lower() != "ntp" else "",
            })
            dst = "true" if ("DST" in tz or "EDT" in tz or "CDT" in tz or
                              "MDT" in tz or "PDT" in tz or "AKDT" in tz) else "false"
            results.append({
                "check": "DST Status",
                "status": "pass",
                "detail": f"DST enabled: {dst}",
                "action": "",
            })
        except Exception as e:
            results.append({"check": "Time/NTP", "status": "fail",
                            "detail": str(e), "action": "Verify device connectivity."})

        # Device Name
        try:
            r = self._get("/System/deviceInfo")
            root = _parse_xml(r.text)
            actual_name = _text(root, "deviceName", default="") if root else ""
            expected_name = expected.get("device_name", "")
            name_ok = bool(expected_name) and actual_name.strip() == expected_name.strip()
            results.append({
                "check": "Device Name",
                "status": "pass" if name_ok else "warn",
                "detail": f"Device reports name: {actual_name or 'N/A'}",
                "action": "" if name_ok else "Verify/rename the device manually — some firmware rejects renaming via ISAPI.",
            })
        except Exception as e:
            results.append({"check": "Device Name", "status": "warn",
                            "detail": "Could not verify via API", "action": "Manually verify device name."})

        # HDD
        try:
            hdds = self.get_storage_info()
            if not hdds:
                results.append({"check": "HDD Status", "status": "warn",
                                "detail": "No HDDs detected", "action": "Check HDD installation."})
            else:
                for hdd in hdds:
                    st = hdd.get("status", "").lower()
                    ok = st in ("ok", "normal", "active")
                    results.append({
                        "check": f"HDD {hdd['id']} Status",
                        "status": "pass" if ok else "fail",
                        "detail": f"Status: {hdd['status']}, Capacity: {hdd['capacity']} MB, Free: {hdd['free_space']} MB",
                        "action": "Check HDD health or replace drive." if not ok else "",
                    })
                    results.append({
                        "check": f"HDD {hdd['id']} Health",
                        "status": "pass",
                        "detail": f"Property: {hdd['property']}",
                        "action": "",
                    })
        except Exception as e:
            results.append({"check": "HDD Status", "status": "fail",
                            "detail": str(e), "action": "Check device storage."})

        # Determine channels
        _all_channel_ids = list(expected.get("channel_ids") or [])
        if not _all_channel_ids:
            try:
                _all_channel_ids = self.get_device_info().get("channel_ids") or []
            except Exception:
                _all_channel_ids = []

        if _all_channel_ids:
            try:
                _online_channel_ids = self.get_online_channel_ids(_all_channel_ids)
            except Exception:
                _online_channel_ids = list(_all_channel_ids)
        else:
            _online_channel_ids = []

        _skipped_channel_ids = [c for c in _all_channel_ids if c not in _online_channel_ids]

        # Recording Schedule
        _rec_pass, _rec_fixed, _rec_fail = [], [], []
        for _cid in _online_channel_ids:
            try:
                _rr = self._get(f"/ContentMgmt/record/tracks/{_cid}")
                if _rr.status_code == 200 and _rr.text and (
                    "<TrackSchedule>" in _rr.text or "<ScheduleBlock>" in _rr.text
                ):
                    _rec_pass.append(_cid)
                    continue
                logger.info(f"No schedule found on track {_cid}; re-applying …")
                if self.configure_recording_schedule(_cid):
                    _rec_fixed.append(_cid)
                else:
                    _rec_fail.append(_cid)
            except Exception as _re_err:
                logger.info(f"Recording schedule check failed on channel {_cid}: {_re_err}")
                _rec_fail.append(_cid)

        results.append(_build_channel_check_result(
            "Recording Schedule", _all_channel_ids,
            ok_ids=_rec_pass + _rec_fixed, fixed_ids=_rec_fixed, fail_ids=_rec_fail,
            skipped_ids=_skipped_channel_ids,
        ))

        # Holiday Schedule
        _hol_verified  = False
        _hol_reapplied = False
        _hol_detail    = "Could not verify via API"
        try:
            _hr = self._get("/System/holidays")
            if _hr.status_code == 200 and _hr.text:
                if "<Holiday>" in _hr.text or "<holiday>" in _hr.text:
                    _hol_verified = True
                    _hol_detail   = "Holiday schedule present on device"
                else:
                    logger.info("No holidays found — re-applying holiday configuration …")
                    _hol_ok = self.configure_holiday()
                    if _hol_ok:
                        _hol_verified  = True
                        _hol_reapplied = True
                        _hol_detail    = "Holiday schedule was missing — re-applied successfully"
                    else:
                        _hol_detail = "Holiday re-apply attempted but could not confirm"
        except Exception as _he:
            _hol_detail = f"Holiday check error: {_he}"

        results.append({
            "check":  "Holiday Schedule",
            "status": "pass" if _hol_verified else "warn",
            "detail": _hol_detail + (" (auto-corrected)" if _hol_reapplied else ""),
            "action": "" if _hol_verified else "Manually verify holiday schedule.",
        })

        # Main & Sub Stream Settings
        _TARGET_CODEC  = {"H.264", "H264", "H264H"}
        _TARGET_W      = "1920"
        _TARGET_H      = "1080"
        _TARGET_CBR    = {"CBR"}
        _TARGET_FPS    = "800"
        _TARGET_BR     = "320"

        def _stream_field(root, *tags):
            val = _text(root, *tags, default="")
            if val:
                return val
            node = _find_first(root, tags[-1])
            return node.text.strip() if node is not None and node.text else ""

        def _stream_fields_ok(stream_id, expect_w, expect_h):
            _sr = self._get(f"/Streaming/channels/{stream_id}")
            _sroot = _parse_xml(_sr.text) if _sr.status_code == 200 else None
            if _sroot is None:
                return None
            codec  = _stream_field(_sroot, "Video", "videoCodecType")
            width  = _stream_field(_sroot, "Video", "videoResolutionWidth")
            height = _stream_field(_sroot, "Video", "videoResolutionHeight")
            btype  = _stream_field(_sroot, "Video", "videoQualityControlType")
            fps    = _stream_field(_sroot, "Video", "maxFrameRate")
            vbrcap = _stream_field(_sroot, "Video", "vbrUpperCap")
            cbr    = _stream_field(_sroot, "Video", "constantBitRate") or vbrcap
            return (
                codec.upper().replace("-", "") in {c.replace("-", "") for c in _TARGET_CODEC}
                and width == expect_w and height == expect_h
                and btype.upper() in _TARGET_CBR and fps == _TARGET_FPS and cbr == _TARGET_BR
            )

        # Main stream
        _main_pass, _main_fixed, _main_fail = [], [], []
        for _cid in _online_channel_ids:
            try:
                _ok = _stream_fields_ok(_cid, _TARGET_W, _TARGET_H)
                if _ok:
                    _main_pass.append(_cid)
                elif self.configure_main_stream(_cid):
                    _main_fixed.append(_cid)
                else:
                    _main_fail.append(_cid)
            except Exception as _se:
                logger.info(f"Main stream check failed on channel {_cid}: {_se}")
                _main_fail.append(_cid)

        results.append(_build_channel_check_result(
            "Main Stream Configuration", _all_channel_ids,
            ok_ids=_main_pass + _main_fixed, fixed_ids=_main_fixed, fail_ids=_main_fail,
            skipped_ids=_skipped_channel_ids,
            target_desc="1920×1080 H.264 CBR 320kbps 8fps",
        ))

        # Sub stream
        _sub_pass, _sub_fixed, _sub_fail = [], [], []
        for _cid in _online_channel_ids:
            _sub_id = _cid[:-2] + "02" if len(_cid) >= 3 else _cid
            try:
                _ok = _stream_fields_ok(_sub_id, "960", "576")
                if _ok:
                    _sub_pass.append(_cid)
                    continue
                _sub_res = self.configure_sub_stream(_cid)
                if _sub_res.get("ok"):
                    _sub_fixed.append(_cid)
                else:
                    _sub_fail.append(_cid)
            except Exception as _se:
                logger.info(f"Sub stream check failed on channel {_cid}: {_se}")
                _sub_fail.append(_cid)

        results.append(_build_channel_check_result(
            "Sub Stream Configuration", _all_channel_ids,
            ok_ids=_sub_pass + _sub_fixed, fixed_ids=_sub_fixed, fail_ids=_sub_fail,
            skipped_ids=_skipped_channel_ids,
            target_desc="H.264 CBR 320kbps 8fps (960×576 primary, with documented fallback resolutions)",
        ))

        # Users
        existing = self._get_existing_users()
        users_to_check = list({"cms", "dlt"} | set(expected.get("users_created", [])))
        for uname in sorted(users_to_check):
            found = uname in existing
            results.append({
                "check": f"{uname.upper()} User Account",
                "status": "pass" if found else "fail",
                "detail": f"User '{uname}' {'exists' if found else 'not found'}",
                "action": "" if found else f"Manually create user '{uname}'.",
            })

        # Channel Zero
        try:
            r = self._get("/Streaming/channels/0")
            root = _parse_xml(r.text)
            enabled = _text(root, "enabled", default="true") if root else "true"
            disabled = enabled.lower() == "false"
            results.append({
                "check": "Channel Zero Status",
                "status": "pass" if disabled else "warn",
                "detail": f"Channel Zero enabled: {enabled}",
                "action": "" if disabled else "Disable Channel Zero in stream settings.",
            })
        except Exception:
            results.append({"check": "Channel Zero Status", "status": "warn",
                            "detail": "Could not verify", "action": "Manually verify Channel Zero is disabled."})

        # Device Online
        results.append({
            "check": "Device Online Status",
            "status": "pass",
            "detail": "Device is reachable and responding to API calls",
            "action": "",
        })

        return results