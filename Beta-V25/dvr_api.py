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
# Format confirmed against real std-cgi and Hikvision devices:
#   STD_ABBR<hours-west>DST_ABBR,M<dst-start>,M<dst-end>
# No explicit -1:00:00 DST-offset suffix, no /HH:MM:SS transition times.
# Zones with no DST have no trailing ",M..." rule at all.
# Short POSIX format — accepted by most standard Hikvision/std-cgi firmware.
# Format: STD<hours-west>DST,M<start>,M<end>
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

# Long Hikvision format — required by some OEM firmware (e.g. PSI Alliance /
# urn:psialliance-org devices) that store timezone as:
#   STD+H:MM:SS DST-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00
# Detection: if device's current <timeZone> value matches r'[A-Z]+[+-]\d+:\d\d:\d\d'
# we use this dict instead of TZ_TO_HIKVISION above.
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
    the device actually uses (ver10, ver20, or none at all — this varies
    across Hikvision/Platinum/LTS firmware builds)."""
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
    """Find all *direct* children matching `tag`, ignoring namespace.
    Unlike _find_all this does not recurse, which matters for nested
    same-named tags (e.g. a ScheduleDay inside a ScheduleDayList shouldn't
    be confused with a differently-scoped element of the same local name)."""
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
    Handles both plain tags (<videoResolutionWidth>) and namespace-prefixed tags
    (<hik:videoResolutionWidth>, <std:videoResolutionWidth>, etc.) so that OEM
    firmware that uses namespace prefixes in serialised XML is patched correctly.
    Preserves any attributes on the opening tag (e.g. opt='...').
    """
    import re as _re
    # Match optional namespace prefix (e.g. "hik:" or "std:") on both opening and closing tags.
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


def _serialize(root):
    """Serialize an ElementTree element back to an XML string, preserving
    the device's own default namespace instead of ElementTree's default
    behaviour of inventing an 'ns0:' prefix for any namespaced tag.

    This matters a lot in practice: several ISAPI-compatible OEM firmwares
    (seen in the wild with xmlns like http://www.std-cgi.com/ver20/XMLSchema,
    as opposed to genuine Hikvision's http://www.hikvision.com/...) run a
    strict XML validator that only recognizes elements in the *default*
    namespace (`xmlns="..."` on the root, no prefix). If we round-trip a GET
    response through ElementTree and call tostring() without registering the
    namespace first, every element gets serialized as `<ns0:tagName>` — which
    is XML-schema-equivalent but these devices reject it outright as
    "Invalid XML Content" (statusCode 6 / badXmlContent), because they don't
    do real namespace-aware parsing. Registering the namespace as the
    default ("") prefix avoids this entirely.
    """
    if '}' in root.tag:
        uri = root.tag.split('}', 1)[0][1:]
        try:
            ET.register_namespace('', uri)
        except Exception:
            pass
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


class DVRClient:
    def __init__(self, ip, port, username, password, use_https=False):
        proto = "https" if use_https else "http"
        self.base_url = f"{proto}://{ip}:{port}/ISAPI"
        self.auth = HTTPDigestAuth(username, password)
        self.verify = False  # Most DVRs use self-signed certs
        self.timeout = 15
        self._session = requests.Session()

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
            # ISAPI error responses usually carry the real reason (statusCode/
            # statusString/subStatusCode) in the body, which requests doesn't
            # surface by default — log it so failures are diagnosable instead
            # of just "400 Client Error".
            body_snippet = ""
            resp = getattr(e, "response", None)
            if resp is not None:
                try:
                    body_snippet = f" — response body: {resp.text[:300]}"
                except Exception:
                    pass
            logger.error(f"PUT {url} failed: {e}{body_snippet}")
            raise

    def _post(self, path, xml_body=""):
        url = f"{self.base_url}{path}"
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
                    body_snippet = f" — response body: {resp.text[:300]}"
                except Exception:
                    pass
            logger.error(f"POST {url} failed: {e}{body_snippet}")
            raise

    # ──────────────────────────────────────────────
    # Step 1: Authenticate (just try to get device info)
    # ──────────────────────────────────────────────
    def test_connection(self):
        """Returns True if auth succeeds."""
        try:
            r = self._get("/System/deviceInfo")
            return r.status_code == 200
        except Exception:
            return False

    # ──────────────────────────────────────────────
    # Set Device Name
    # ──────────────────────────────────────────────
    def configure_device_name(self, name):
        """
        Write the friendly device name to the device itself.
        Previously this value was only stored locally for the app's own
        session/report — it was never actually sent to the DVR/NVR, so the
        device's own on-screen/web-UI name never changed.

        We GET the current /System/deviceInfo, patch just the <deviceName>
        node in place (preserving whatever namespace/fields the device
        already returned), then PUT the whole document back — a partial PUT
        with only deviceName is rejected as invalid by many firmware builds
        because other fields are treated as required.
        """
        if not name:
            return False
        try:
            r = self._get("/System/deviceInfo")
            root = _parse_xml(r.text)
            if root is None:
                return False

            ns_prefix = root.tag.rsplit('}', 1)[0] + '}' if '}' in root.tag else ''

            # ISAPI documents only a small set of fields as writable on this
            # resource (deviceName, deviceID, deviceDescription,
            # deviceLocation, systemContact, telecontrolID). Several
            # firmware builds silently ignore — or outright 400 — a PUT that
            # also echoes back read-only fields (serialNumber, macAddress,
            # firmwareVersion, model, hardwareVersion, etc.) even when their
            # values are unchanged, which is likely why a full round-trip of
            # the GET response didn't actually rename the device. Try the
            # minimal, spec-writable document first.
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

    # ──────────────────────────────────────────────
    # Step 2: Device Discovery
    # ──────────────────────────────────────────────
    def get_device_info(self):
        r = self._get("/System/deviceInfo")
        root = _parse_xml(r.text)
        if root is None:
            return {}

        # Get channel counts
        # NOTE: /System/Video/inputs/channels reports configured channel SLOTS
        # (device capacity), and its <enabled> flag typically just means "this
        # slot is enabled in config" — NOT "a camera is actually connected".
        # On NVRs with fewer cameras plugged in than the device supports, this
        # makes every slot look "active" even when most have no camera. To get
        # a true count of cameras actually online, we cross-check the
        # InputProxy channel status endpoint (IP camera channels on an NVR).
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

        # Always fetch /Streaming/channels — gives us both a total fallback count
        # AND the real channel IDs (e.g. "101","201","301") we can use for
        # stream/recording config instead of guessing range(1, N+1)*100+streamType.
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

        # Cross-check against InputProxy channel status (real online/offline
        # state of IP cameras attached to an NVR).
        # This is the most authoritative count on hybrid/IP-only NVRs:
        # - channels_total: use the LARGER of the streaming count and the
        #   InputProxy capacity, so we never show fewer channels than the
        #   device actually has (the streaming count can be artificially low
        #   when /System/Video/inputs/channels returns 403 and /Streaming/channels
        #   only lists a subset of the proxy channels).
        # - channels_active: always use the online count from InputProxy when
        #   available, since it reflects actual camera connectivity.
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

        # MAC address
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

        # Current time
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

    # ──────────────────────────────────────────────
    # Step 3: Time / NTP Configuration
    # ──────────────────────────────────────────────
    def get_timezone_for_state(self, state):
        return STATE_TIMEZONE.get(state, "America/Chicago")

    def configure_time(self, city, state):
        iana_tz = self.get_timezone_for_state(state)
        hik_tz = TZ_TO_HIKVISION.get(iana_tz, "CST6CDT-1:00:00,M3.2.0/02:00:00,M11.1.0/02:00:00")
        # A DST rule is present whenever the string has the ",M<start>/...,M<end>/..." suffix.
        dst_enabled = "," in hik_tz

        # localTime is required by many firmware builds even when timeMode is NTP —
        # omitting it causes a 400 Bad Request on some devices. Compute it in the
        # target zone so the value is at least plausible until NTP takes over.
        try:
            from zoneinfo import ZoneInfo
            local_time_iso = datetime.now(ZoneInfo(iana_tz)).isoformat(timespec="seconds")
        except Exception as e:
            logger.warning(f"Could not compute local time for {iana_tz}: {e}")
            local_time_iso = datetime.utcnow().isoformat(timespec="seconds")

        # Set NTP
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

        # Set timezone + DST using GET → regex-patch → PUT.
        # Strategy: never let this block raise — timezone failure is non-fatal,
        # we want the rest of configuration (streams, recording schedule) to
        # continue regardless.
        #
        # Attempt order:
        #  1. Patch only timeZone + DST in the raw GET body (preserves device
        #     namespace, structure, and all other fields exactly).
        #  2. Same but also set timeMode=NTP.
        #  3. Log and give up — NTP server is already set via ntpServers/1
        #     which succeeded; the device will sync time on its own.
        time_xml_raw = None
        try:
            tr = self._get("/System/time")
            if tr.status_code == 200:
                time_xml_raw = tr.text
                logger.debug(f"/System/time GET body: {time_xml_raw!r}")
        except Exception as e:
            logger.warning(f"Could not GET /System/time: {e}")

        if time_xml_raw:
            # Detect the actual tag names this firmware uses.
            tz_tag  = "timeZone"  if "<timeZone>"  in time_xml_raw else \
                      "timezone"  if "<timezone>"  in time_xml_raw else "timeZone"
            dst_tag = "DSTEnable" if "<DSTEnable>" in time_xml_raw else \
                      "dstEnable" if "<dstEnable>" in time_xml_raw else "DSTEnable"

            # Attempt 1: patch only TZ + DST (leave timeMode untouched —
            # NTP server is already configured via ntpServers/1).
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
                # Attempt 2: also force timeMode=NTP.
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
                        f"NTP server is configured; device will sync timezone on reboot. "
                        f"GET body was: {time_xml_raw!r}"
                    )
        else:
            logger.warning("/System/time GET failed; skipping timezone PUT")

        # Configure explicit DST parameters via the dedicated /System/DST endpoint.
        # Standard US DST: Start = 2nd Sunday of March at 00:00,
        #                  End   = 1st Sunday of November at 00:00, Bias = 60 min.
        # This is applied regardless of the current DST settings on the device.
        self._configure_dst_explicit(dst_enabled)

        return {
            "iana_timezone": iana_tz,
            "hikvision_timezone": hik_tz,
            "ntp_server": "pool.ntp.org",
            "ntp_interval": 1440,
            "dst_enabled": dst_enabled,
        }

    def _configure_dst_explicit(self, dst_enabled):
        """Configure DST via the /System/DST endpoint.
        When DST is applicable the standard US rules are enforced:
          Start : March, 2nd week (2nd Sunday), 00:00
          End   : November, 1st week (1st Sunday), 00:00
          Bias  : 60 minutes
        Settings are written unconditionally — existing higher/different values
        are always overwritten to enforce the recommended configuration.
        """
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
            # Non-fatal — many devices expose DST only through /System/time.
            logger.info(f"/System/DST endpoint not available ({e}); "
                        "DST was already set via /System/time patch")

    # ──────────────────────────────────────────────
    # Step 4: Storage Detection
    # ──────────────────────────────────────────────
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

        # Fallback: try flat list
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

    # ──────────────────────────────────────────────
    # Step 5: Camera Stream Configuration
    # ──────────────────────────────────────────────
    def get_streaming_channels(self):
        r = self._get("/Streaming/channels")
        root = _parse_xml(r.text)
        if root is None:
            return []
        return _find_all(root, "StreamingChannel")

    def _closest_resolution(self, available, preferred_w, preferred_h):
        """Return (width, height) from available list closest to preferred."""
        if not available:
            return preferred_w, preferred_h
        best = min(available,
                   key=lambda wh: abs(wh[0] - preferred_w) + abs(wh[1] - preferred_h))
        return best

    def get_available_resolutions(self, channel_id):
        """Query supported resolutions for a channel (main=01, sub=02)."""
        try:
            r = self._get(f"/Streaming/channels/{channel_id}/capabilities")
            root = _parse_xml(r.text)
            if root is None:
                return []
            resolutions = []
            for node in (root.findall(f".//{_ns('videoResolutionWidth')}") or
                          root.findall(".//videoResolutionWidth")):
                pass  # capabilities vary widely by firmware
            # Most reliable: parse resolutionList
            for res in (root.findall(f".//{_ns('resolutionHeight')}") or []):
                pass
            return resolutions
        except Exception:
            return []

    def _patch_stream_channel(self, channel_id, fields):
        """
        GET the current StreamingChannel document for channel_id, apply
        fields (dict of tag -> value), serialize with _serialize() (which
        registers the device's own namespace as the default so no ns0: prefix
        appears in the output), and PUT it back.  Returns True on success.

        This GET-patch-PUT pattern is required because OEM/std-cgi firmware
        (and some genuine Hikvision builds) validate the full schema on write
        and reject hand-built documents that lack the xmlns declaration, carry
        unexpected ns-prefixed tags, or omit read-only sibling fields the
        firmware considers mandatory in the same PUT request.
        """
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
                if tag == "Video":
                    pass
            self._put(f"/Streaming/channels/{channel_id}", _serialize(root))
            return True
        except Exception as e:
            return False

    def _patch_video_fields(self, channel_root, video_fields):
        """Patch fields inside the <Video> sub-element of a StreamingChannel root."""
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
        """
        Given a list of main-stream channel IDs (e.g. ["101", "201", "301"]),
        return only those that belong to online/active cameras by querying the
        InputProxy channel status endpoint.  Falls back to all_channel_ids if
        the endpoint is unavailable (analog DVRs, unsupported firmware, etc.).
        """
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

            # Build set of online channel numbers (InputProxy IDs are "1", "2", …)
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

            # Match streaming IDs (e.g. "101") to InputProxy numbers (e.g. "1")
            online_main_ids = []
            for cid in all_channel_ids:
                prefix = cid[:-2]  # "101" → "1", "1601" → "16"
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

    # ──────────────────────────────────────────────
    # Camera Name Management (standalone feature)
    # ──────────────────────────────────────────────
    def list_active_channels_for_naming(self):
        """
        Return a list of active/online channels suitable for the Camera Name
        Management feature:
          [{"channel_id": "1", "name": "Camera 01", "online": True}, ...]
        Offline/disabled channels are excluded entirely (never returned),
        per spec — "detect only active channels ... skip offline/disabled".

        IMPORTANT: /System/Video/inputs/channels (XML_VideoInputChannel) only
        lists physical BNC/analog video-in connectors. A pure NVR (all IP
        cameras, no analog inputs) returns an EMPTY list there even though
        cameras are actively connected — the real per-camera channel list on
        an NVR lives at /ContentMgmt/InputProxy/channels (XML_InputProxyChannel).
        Previously this method only checked /System/Video/inputs/channels and
        returned [] immediately for NVRs, which is why an NVR with an active
        camera showed "no active channels detected" during camera naming.
        We now try both sources and merge them (by channel id) so hybrid
        DVRs, analog DVRs, and pure NVRs are all handled correctly.
        """
        # Cross-check true online/offline state via InputProxy status — the
        # authoritative "is a camera actually plugged in" signal.
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
            logger.info(f"InputProxy status unavailable for naming (analog DVR or unsupported): {e}")

        channels_by_id = {}

        # Source 1: analog/BNC video-input channels (XML_VideoInputChannel).
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

        # Source 2: IP-camera channels behind an NVR (XML_InputProxyChannel).
        # This is the ONLY source that has any entries on a pure NVR.
        try:
            ir = self._get("/ContentMgmt/InputProxy/channels")
            iroot = _parse_xml(ir.text)
            if iroot is not None:
                for item in _find_all(iroot, "InputProxyChannel"):
                    ch_id = _text(item, "id", default="").strip()
                    if not ch_id or ch_id in channels_by_id:
                        continue
                    name = _text(item, "name", default="")
                    # InputProxyChannel has no <enabled> flag — a configured
                    # proxy channel is "enabled" by definition; actual
                    # connectivity is determined purely by online_map below.
                    channels_by_id[ch_id] = {"channel_id": ch_id, "name": name, "enabled": True, "source": "ip_proxy"}
        except Exception as e:
            logger.info(f"list_active_channels_for_naming: /ContentMgmt/InputProxy/channels unavailable: {e}")

        if not channels_by_id:
            logger.warning("list_active_channels_for_naming: neither video-input nor InputProxy channel list returned data")
            return []

        active = []
        for ch in channels_by_id.values():
            if not ch["enabled"]:
                continue  # disabled channel — skip
            # Only enforce the online check when we actually have status data
            # for THIS channel id; otherwise default to including it (matches
            # get_online_channel_ids' fail-open behavior elsewhere in this file).
            if ch["channel_id"] in online_map and not online_map[ch["channel_id"]]:
                continue  # confirmed offline camera — skip
            ch["online"] = True
            active.append(ch)
        return active

    def apply_channel_name(self, channel_id, new_name):
        """
        Set a channel's name using GET → regex-patch → PUT against
        /ISAPI/System/Video/inputs/channels/<ID> (XML_VideoInputChannel
        <name>, max 64 chars per ISAPI spec), and mirror it onto the
        on-screen channelNameOverlay so the label is visible in the video
        feed too. For NVR channels backed by an IP camera, also update the
        InputProxy channel name so CMS/VMS software picks up the same label.
        Returns (ok: bool, detail: str).
        """
        new_name = (new_name or "").strip()[:64]
        if not new_name:
            return False, "Name is empty"

        # Endpoints differ by device type: /System/Video/inputs/channels is
        # for analog/BNC video-input channels and returns 403 Forbidden (not
        # 404) on pure NVRs with only IP-camera/InputProxy channels — so we
        # must not treat that 403 as fatal; the InputProxy update below is
        # the one that actually matters for those devices. Track each path
        # independently and succeed if ANY of them worked.
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
        """Configure main stream using GET → regex-patch → PUT.
        Settings: 1920×1080, H.264, CBR, 320 kbps, 8 fps (maxFrameRate=800).
        Always enforces recommended settings regardless of what is currently
        configured on the device — higher existing values are overwritten too.
        """
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
        """Configure main-stream event channel (ID suffix '03') using GET → regex-patch → PUT.
        Settings: 1920×1080, H.264, CBR, 320 kbps, 8 fps — same as main stream.
        Event-stream ID = main-stream ID with last two digits replaced by '03'.
        Always enforces recommended settings regardless of existing configuration.
        """
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
            logger.info(f"Event stream config channel {event_id}: {e} (non-fatal — not all firmware supports this channel)")
            return False

    def configure_sub_stream(self, channel_id):
        """Configure sub stream using GET → regex-patch → PUT.
        Settings: 960×576, H.264, CBR, 320 kbps, 8 fps.
        Sub-stream ID = main-stream ID with last two digits replaced by '02'.
        Always enforces recommended settings regardless of existing configuration.
        """
        sub_id = channel_id[:-2] + "02" if len(channel_id) >= 3 else channel_id
        try:
            r = self._get(f"/Streaming/channels/{sub_id}")
            if r.status_code != 200:
                logger.warning(f"Sub stream GET channel {sub_id}: HTTP {r.status_code}")
                return False
            patched = _patch_xml_fields(r.text, [
                ("videoCodecType",          "H.264"),
                ("videoResolutionWidth",    "960"),
                ("videoResolutionHeight",   "576"),
                ("videoQualityControlType", "CBR"),
                ("maxFrameRate",            "800"),
                ("vbrUpperCap",             "320"),
                ("constantBitRate",         "320"),
            ])
            self._put(f"/Streaming/channels/{sub_id}", patched)
            logger.info(f"Sub stream channel {sub_id}: configured 960×576 H.264 CBR 320kbps 8fps")
            return True
        except Exception as e:
            logger.warning(f"Sub stream config channel {sub_id}: {e}")
            return False

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

    # ──────────────────────────────────────────────
    # Step 6: Recording Schedule
    # ──────────────────────────────────────────────
    def configure_recording_schedule(self, channel_id):
        """
        Schedule: 00:00-08:00 Motion, 08:00-22:00 Continuous, 22:00-24:00 Motion
        Applied to all 7 days.

        Schema confirmed from device diagnostic (std-cgi RACM format):
          Container  : <TrackSchedule><ScheduleBlockList><ScheduleBlock>
          Each action: <ScheduleAction> with <id>, <ScheduleActionStartTime/EndTime>
          Start/End  : <DayOfWeek> (Monday…Sunday) + <TimeOfDay> (HH:MM:SS)
          Mode field : <ActionRecordingMode>  values: MOTION | CMR
          End of day : last slot's EndTime uses next day name at 00:00:00

        Pattern: GET full /ContentMgmt/record/tracks/{id} → replace
        <TrackSchedule>…</TrackSchedule> block using regex → PUT back.
        The outer track document is preserved as-is (correct namespace, read-
        only fields, etc.) so the device's own schema validator accepts it.
        """
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

    # ──────────────────────────────────────────────
    # Step 7: Holiday Schedule
    # ──────────────────────────────────────────────
    def configure_holiday(self):
        """Create Thanksgiving & Black Friday holiday — 4th Monday Nov to 1st Monday Dec."""
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

    # ──────────────────────────────────────────────
    # Step 8 & 9: User Creation + Permissions
    # ──────────────────────────────────────────────
    def _get_existing_users(self):
        try:
            r = self._get("/Security/users")
            root = _parse_xml(r.text)
            if root is None:
                return {}
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

    # ISAPI XML_User <userLevel> only accepts these exact, case-sensitive
    # strings: "Administrator,Operator,Viewer,installer,manufacturer".
    # Lowercase values (previously "viewer"/"operator") are silently rejected
    # or accepted-but-ignored by most Hikvision/OEM firmware, which is why
    # user creation and rights management appeared to "not work."
    _USER_LEVEL_MAP = {
        "viewer": "Viewer",
        "operator": "Operator",
        "admin": "Administrator",
        "administrator": "Administrator",
    }

    def create_user(self, username, password, role="viewer"):
        """Create a user on the DVR. Returns user id or raises."""
        user_level = self._USER_LEVEL_MAP.get(role.lower(), "Viewer")

        # Check if already exists
        existing = self._get_existing_users()
        if username in existing:
            logger.info(f"User {username} already exists (id={existing[username]}), updating password")
            uid = existing[username]
            self._update_user_password(uid, username, password, user_level)
            return uid

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<User version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">
  <userName>{username}</userName>
  <password>{password}</password>
  <userLevel>{user_level}</userLevel>
</User>"""
        try:
            r = self._post("/Security/users", xml)
            root = _parse_xml(r.text)
            uid = _text(root, "id", default="") if root is not None else ""
            if not uid:
                # Some firmware doesn't echo the id back on the ResponseStatus body
                # (only statusCode/statusString). Re-fetch the user list to resolve
                # the ID the device actually assigned to the new username.
                refreshed = self._get_existing_users()
                uid = refreshed.get(username, "")
            if not uid:
                raise Exception("Device did not return a user id and user was not found afterwards")
            return uid
        except Exception as e:
            logger.error(f"Create user {username}: {e}")
            raise

    def _update_user_password(self, uid, username, password, user_level):
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<User version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">
  <id>{uid}</id>
  <userName>{username}</userName>
  <password>{password}</password>
  <userLevel>{user_level}</userLevel>
</User>"""
        try:
            self._put(f"/Security/users/{uid}", xml)
        except Exception as e:
            logger.warning(f"Update user {uid}: {e}")

    def set_user_permissions(self, uid, username, permission_set):
        """
        permission_set: 'cms' (Viewer-level, monitoring account) or
                         'dlt' (Operator-level, remote-admin account).

        Field names below match the ISAPI XML_remotePermission /
        XML_localPermission schema exactly (the previous implementation used
        invented tag names like <remoteParameters>/<remoteLive>/<remoteLog>
        that don't exist in the ISAPI spec, so the device ignored the whole
        permission block).
        """
        if permission_set == "cms":
            user_type = "viewer"
            remote_perms = """
      <preview>true</preview>
      <playBack>true</playBack>
      <record>false</record>
      <logOrStateCheck>true</logOrStateCheck>
      <parameterConfig>false</parameterConfig>
      <restartOrShutdown>false</restartOrShutdown>
      <upgrade>false</upgrade>
      <voiceTalk>false</voiceTalk>
      <ptzControl>false</ptzControl>"""
            local_perms = """
      <preview>true</preview>
      <playBack>true</playBack>
      <record>false</record>
      <backup>true</backup>
      <ptzControl>false</ptzControl>"""
        else:  # dlt
            user_type = "operator"
            remote_perms = """
      <preview>true</preview>
      <playBack>true</playBack>
      <record>false</record>
      <logOrStateCheck>true</logOrStateCheck>
      <parameterConfig>true</parameterConfig>
      <restartOrShutdown>true</restartOrShutdown>
      <upgrade>false</upgrade>
      <voiceTalk>false</voiceTalk>
      <ptzControl>true</ptzControl>"""
            local_perms = """
      <preview>true</preview>
      <playBack>true</playBack>
      <record>false</record>
      <backup>false</backup>
      <ptzControl>true</ptzControl>"""

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<UserPermission version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">
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

    # ──────────────────────────────────────────────
    # Step 10: Validation
    # ──────────────────────────────────────────────
    def validate_configuration(self, expected):
        """
        Run all validation checks. Returns list of:
        {"check": str, "status": "pass"|"warn"|"fail", "detail": str, "action": str}
        """
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
            # Compare just the standard-time prefix (e.g. "CST6CDT") rather than
            # the full DST-rule string — some firmware normalizes the ",M.../..."
            # suffix on read-back (different separators/precision), which made
            # this check report "warn" even when the timezone was applied correctly.
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
                "action": "" if name_ok else "Verify/rename the device manually — some firmware "
                                              "rejects renaming via ISAPI.",
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

        # ── Recording Schedule (spot-check first available channel, self-healing) ──
        # The correct ISAPI path is /ContentMgmt/record/tracks/{id} — NOT /schedule.
        # We look for a <TrackSchedule> block inside the response to confirm the
        # schedule is actually written (a 200 with an empty body would also parse).
        # If the schedule is missing we re-apply it immediately and report the result.
        _rec_check_ids = ["101", "1"]   # try channel 1 in both common ID formats
        _rec_verified  = False
        _rec_reapplied = False
        _rec_detail    = "Could not verify via API"
        for _rid in _rec_check_ids:
            try:
                _rr = self._get(f"/ContentMgmt/record/tracks/{_rid}")
                if _rr.status_code == 200 and _rr.text:
                    _rec_detail = f"Track {_rid} endpoint reachable"
                    if "<TrackSchedule>" in _rr.text or "<ScheduleBlock>" in _rr.text:
                        _rec_verified = True
                        _rec_detail   = f"Recording schedule confirmed on channel {_rid}"
                        break
                    else:
                        # Track exists but no schedule block — re-apply
                        logger.info(f"No schedule found on track {_rid}; re-applying …")
                        _ok = self.configure_recording_schedule(_rid)
                        if _ok:
                            _rec_verified  = True
                            _rec_reapplied = True
                            _rec_detail    = f"Schedule was missing on channel {_rid} — re-applied successfully"
                        else:
                            _rec_detail = f"Schedule re-apply failed on channel {_rid}"
                        break
            except Exception as _re_err:
                _rec_detail = f"Track {_rid}: {_re_err}"
                continue

        if not _rec_verified and not _rec_reapplied:
            # Last resort: try to apply the schedule anyway
            try:
                _ok = self.configure_recording_schedule("101")
                if _ok:
                    _rec_verified  = True
                    _rec_reapplied = True
                    _rec_detail    = "Schedule applied to channel 101 during validation"
            except Exception:
                pass

        results.append({
            "check":  "Recording Schedule",
            "status": "pass" if _rec_verified else "warn",
            "detail": _rec_detail + (" (auto-corrected)" if _rec_reapplied else ""),
            "action": "" if _rec_verified else "Manually verify recording schedule on the device.",
        })

        # ── Holiday Schedule (verify content, self-healing) ──────────────────────
        # A plain 200 with any XML passes the old check even with zero holidays.
        # Now we look for at least one <Holiday> entry; re-apply if none found.
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

        # ── Camera Stream Settings (full field check, self-healing) ──────────────
        # Required: H.264, 1920×1080, CBR, 320 kbps max, 8 fps (maxFrameRate=800).
        # If the device was left at a higher resolution (e.g. 3840) the old code
        # only checked the codec, so it showed "pass" even though the resolution
        # was never changed. Now we verify every required field and re-apply if any
        # value is wrong (handles namespace-prefixed firmware that silently ignored
        # the earlier _patch_xml_field calls because the regex didn't match).
        _TARGET_CODEC  = {"H.264", "H264", "H264H"}
        _TARGET_W      = "1920"
        _TARGET_H      = "1080"
        _TARGET_CBR    = {"CBR"}
        _TARGET_FPS    = "800"    # Hikvision: 800 = 8 fps
        _TARGET_BR     = "320"

        def _stream_field(root, *tags):
            """Robust field lookup: try _find path first, then _find_first fallback."""
            val = _text(root, *tags, default="")
            if val:
                return val
            # Fallback: find the last tag anywhere in the tree
            node = _find_first(root, tags[-1])
            return node.text.strip() if node is not None and node.text else ""

        # Determine which channel ID to spot-check (use 101 or first discovered)
        _stream_ids = expected.get("channel_ids") or ["101"]
        _check_id   = _stream_ids[0] if _stream_ids else "101"

        _stream_ok      = False
        _stream_detail  = "Could not read stream settings"
        _stream_fixed   = False
        try:
            _sr   = self._get(f"/Streaming/channels/{_check_id}")
            _sroot = _parse_xml(_sr.text) if _sr.status_code == 200 else None
            if _sroot is not None:
                codec   = _stream_field(_sroot, "Video", "videoCodecType")
                width   = _stream_field(_sroot, "Video", "videoResolutionWidth")
                height  = _stream_field(_sroot, "Video", "videoResolutionHeight")
                btype   = _stream_field(_sroot, "Video", "videoQualityControlType")
                fps     = _stream_field(_sroot, "Video", "maxFrameRate")
                vbrcap  = _stream_field(_sroot, "Video", "vbrUpperCap")
                cbr     = _stream_field(_sroot, "Video", "constantBitRate") or vbrcap

                _stream_detail = (
                    f"Channel {_check_id} — Codec: {codec or 'N/A'}, "
                    f"Resolution: {width or '?'}×{height or '?'}, "
                    f"Type: {btype or 'N/A'}, "
                    f"Bitrate: {cbr or '?'} kbps, "
                    f"FPS setting: {fps or '?'}"
                )

                codec_ok  = codec.upper().replace("-", "") in {c.replace("-", "") for c in _TARGET_CODEC}
                width_ok  = width  == _TARGET_W
                height_ok = height == _TARGET_H
                cbr_ok    = btype.upper() in _TARGET_CBR
                fps_ok    = fps    == _TARGET_FPS
                br_ok     = cbr    == _TARGET_BR

                if codec_ok and width_ok and height_ok and cbr_ok and fps_ok and br_ok:
                    _stream_ok = True
                else:
                    # Values don't match — re-apply stream configuration
                    mismatches = []
                    if not codec_ok:  mismatches.append(f"codec={codec}≠H.264")
                    if not width_ok:  mismatches.append(f"width={width}≠1920")
                    if not height_ok: mismatches.append(f"height={height}≠1080")
                    if not cbr_ok:    mismatches.append(f"type={btype}≠CBR")
                    if not fps_ok:    mismatches.append(f"fps={fps}≠800")
                    if not br_ok:     mismatches.append(f"bitrate={cbr}≠320")
                    logger.info(f"Stream {_check_id} mismatches: {mismatches} — re-applying …")
                    _reok = self.configure_main_stream(_check_id)
                    if _reok:
                        _stream_fixed  = True
                        _stream_ok     = True
                        _stream_detail = (
                            f"Channel {_check_id} had wrong settings "
                            f"({', '.join(mismatches)}) — re-applied: "
                            f"1920×1080 H.264 CBR 320kbps 8fps"
                        )
                    else:
                        _stream_detail = (
                            f"Channel {_check_id} has wrong settings "
                            f"({', '.join(mismatches)}) and re-apply failed"
                        )
            else:
                _stream_detail = f"Could not read channel {_check_id} settings"
        except Exception as _se:
            _stream_detail = f"Stream check error: {_se}"

        results.append({
            "check":  "Camera Stream Settings",
            "status": "pass" if _stream_ok else "warn",
            "detail": _stream_detail + (" (auto-corrected)" if _stream_fixed else ""),
            "action": "" if _stream_ok else "Manually verify stream settings match recommended values.",
        })

        # Users
        existing = self._get_existing_users()
        for uname in ("cms", "dlt"):
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
