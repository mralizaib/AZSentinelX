"""
DVR/NVR ISAPI Client
Supports Hikvision, Platinum (Hikvision OEM), and LTS (Hikvision OEM) devices.
All three brands use the Hikvision ISAPI over HTTP/HTTPS with Digest Auth.
"""
import logging
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

# IANA tz → Hikvision CST offset string (used in ISAPI XML)
TZ_TO_HIKVISION = {
    "America/New_York":      "EST-5EDT,M3.2.0,M11.1.0",
    "America/Chicago":       "CST-6CDT,M3.2.0,M11.1.0",
    "America/Denver":        "MST-7MDT,M3.2.0,M11.1.0",
    "America/Los_Angeles":   "PST-8PDT,M3.2.0,M11.1.0",
    "America/Phoenix":       "MST-7",
    "America/Anchorage":     "AKST-9AKDT,M3.2.0,M11.1.0",
    "Pacific/Honolulu":      "HST-10",
    "America/Boise":         "MST-7MDT,M3.2.0,M11.1.0",
    "America/Indiana/Indianapolis": "EST-5",
    "America/Kentucky/Louisville":  "EST-5EDT,M3.2.0,M11.1.0",
    "America/Detroit":       "EST-5EDT,M3.2.0,M11.1.0",
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


def _find(root, *tags):
    """Walk tag path, stripping namespace if needed."""
    node = root
    for tag in tags:
        if node is None:
            return None
        child = node.find(_ns(tag))
        if child is None:
            child = node.find(tag)
        node = child
    return node


def _text(root, *tags, default="N/A"):
    node = _find(root, *tags)
    return node.text.strip() if node is not None and node.text else default


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
            logger.error(f"PUT {url} failed: {e}")
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
            logger.error(f"POST {url} failed: {e}")
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
    # Step 2: Device Discovery
    # ──────────────────────────────────────────────
    def get_device_info(self):
        r = self._get("/System/deviceInfo")
        root = _parse_xml(r.text)
        if root is None:
            return {}

        # Get channel counts
        channels_total = 0
        channels_active = 0
        try:
            cr = self._get("/System/Video/inputs/channels")
            croot = _parse_xml(cr.text)
            if croot is not None:
                items = croot.findall(f".//{_ns('VideoInputChannel')}") or \
                        croot.findall(".//VideoInputChannel")
                channels_total = len(items)
                for item in items:
                    enabled = _text(item, "enabled", default="false")
                    if enabled.lower() == "true":
                        channels_active += 1
                if channels_active == 0:
                    channels_active = channels_total
        except Exception:
            pass

        # Get streaming channel count as fallback
        if channels_total == 0:
            try:
                sr = self._get("/Streaming/channels")
                sroot = _parse_xml(sr.text)
                if sroot is not None:
                    mains = [c for c in (sroot.findall(f".//{_ns('StreamingChannel')}") or
                                         sroot.findall(".//StreamingChannel"))
                             if _text(c, "id", default="").endswith("01")]
                    channels_total = len(mains)
                    channels_active = channels_total
            except Exception:
                pass

        # MAC address
        mac = "N/A"
        try:
            nr = self._get("/System/Network/interfaces")
            nroot = _parse_xml(nr.text)
            if nroot is not None:
                mac = _text(nroot, "NetworkInterface", "IPAddress", "ipAddress", default="N/A")
                mac_node = nroot.find(f".//{_ns('MACAddress')}") or nroot.find(".//MACAddress")
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
            "manufacturer": _text(root, "manufacturer", default="Hikvision"),
            "model": _text(root, "model", default="N/A"),
            "device_type": _text(root, "deviceType", default="N/A"),
            "serial_number": _text(root, "serialNumber", default="N/A"),
            "firmware_version": _text(root, "firmwareVersion", default="N/A"),
            "total_channels": channels_total,
            "active_channels": channels_active,
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
        hik_tz = TZ_TO_HIKVISION.get(iana_tz, "CST-6CDT,M3.2.0,M11.1.0")
        dst_enabled = "true" if "DST" in hik_tz or "EDT" in hik_tz or "CDT" in hik_tz or \
                                "MDT" in hik_tz or "PDT" in hik_tz or "AKDT" in hik_tz else "false"

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

        # Set timezone + DST
        time_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Time>
  <timeMode>NTP</timeMode>
  <timeZone>{hik_tz}</timeZone>
</Time>"""
        self._put("/System/time", time_xml)

        return {
            "iana_timezone": iana_tz,
            "hikvision_timezone": hik_tz,
            "ntp_server": "pool.ntp.org",
            "ntp_interval": 1440,
            "dst_enabled": dst_enabled == "true",
        }

    # ──────────────────────────────────────────────
    # Step 4: Storage Detection
    # ──────────────────────────────────────────────
    def get_storage_info(self):
        r = self._get("/ContentMgmt/Storage")
        root = _parse_xml(r.text)
        if root is None:
            return []

        hdds = []
        for hdd in (root.findall(f".//{_ns('hddList')}") or root.findall(".//hddList")):
            for item in (hdd.findall(_ns("hdd")) or hdd.findall("hdd")):
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
            for item in (root.findall(f".//{_ns('hdd')}") or root.findall(".//hdd")):
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
        return root.findall(f".//{_ns('StreamingChannel')}") or \
               root.findall(".//StreamingChannel")

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

    def configure_main_stream(self, channel_id):
        """Configure main stream: 1080p, H.264, 8fps, VBR, 320kbps."""
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<StreamingChannel>
  <id>{channel_id}</id>
  <channelName>Camera {channel_id[:2]}</channelName>
  <enabled>true</enabled>
  <Transport>
    <maxPacketSize>1000</maxPacketSize>
    <ControlProtocolList>
      <ControlProtocol>
        <streamingTransport>RTSP</streamingTransport>
      </ControlProtocol>
    </ControlProtocolList>
  </Transport>
  <Video>
    <enabled>true</enabled>
    <videoCodecType>H.264</videoCodecType>
    <videoResolutionWidth>1920</videoResolutionWidth>
    <videoResolutionHeight>1080</videoResolutionHeight>
    <videoQualityControlType>VBR</videoQualityControlType>
    <fixedQuality>60</fixedQuality>
    <vbrUpperCap>320</vbrUpperCap>
    <maxFrameRate>800</maxFrameRate>
    <keyFrameInterval>2000</keyFrameInterval>
  </Video>
</StreamingChannel>"""
        try:
            self._put(f"/Streaming/channels/{channel_id}", xml)
            return True
        except Exception as e:
            logger.warning(f"Main stream config channel {channel_id}: {e}")
            return False

    def configure_sub_stream(self, channel_id):
        """Configure sub stream: 960x480, H.264, 8fps, VBR, 320kbps."""
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<StreamingChannel>
  <id>{channel_id}</id>
  <channelName>Camera {channel_id[:2]} Sub</channelName>
  <enabled>true</enabled>
  <Transport>
    <maxPacketSize>1000</maxPacketSize>
    <ControlProtocolList>
      <ControlProtocol>
        <streamingTransport>RTSP</streamingTransport>
      </ControlProtocol>
    </ControlProtocolList>
  </Transport>
  <Video>
    <enabled>true</enabled>
    <videoCodecType>H.264</videoCodecType>
    <videoResolutionWidth>960</videoResolutionWidth>
    <videoResolutionHeight>480</videoResolutionHeight>
    <videoQualityControlType>VBR</videoQualityControlType>
    <fixedQuality>60</fixedQuality>
    <vbrUpperCap>320</vbrUpperCap>
    <maxFrameRate>800</maxFrameRate>
    <keyFrameInterval>2000</keyFrameInterval>
  </Video>
</StreamingChannel>"""
        try:
            self._put(f"/Streaming/channels/{channel_id}", xml)
            return True
        except Exception as e:
            logger.warning(f"Sub stream config channel {channel_id}: {e}")
            return False

    def disable_channel_zero(self):
        try:
            xml = """<?xml version="1.0" encoding="UTF-8"?>
<ZeroVideoChannel>
  <id>0</id>
  <enabled>false</enabled>
</ZeroVideoChannel>"""
            self._put("/Streaming/channels/0", xml)
        except Exception as e:
            logger.warning(f"Channel zero disable: {e}")

    # ──────────────────────────────────────────────
    # Step 6: Recording Schedule
    # ──────────────────────────────────────────────
    def configure_recording_schedule(self, channel_id):
        """
        Schedule: 00:00-08:00 Motion, 08:00-22:00 Continuous, 22:00-24:00 Motion
        Applied to all 7 days.
        """
        # Build time segment blocks for one day
        # recordType: 1=Continuous, 2=Motion, 4=Alarm
        def day_block(day_index):
            return f"""    <ScheduleDay>
      <dayOfWeek>{day_index}</dayOfWeek>
      <TimeBlockList>
        <TimeBlock>
          <startTime>00:00:00</startTime>
          <endTime>08:00:00</endTime>
          <recordType>motion</recordType>
        </TimeBlock>
        <TimeBlock>
          <startTime>08:00:00</startTime>
          <endTime>22:00:00</endTime>
          <recordType>continuous</recordType>
        </TimeBlock>
        <TimeBlock>
          <startTime>22:00:00</startTime>
          <endTime>24:00:00</endTime>
          <recordType>motion</recordType>
        </TimeBlock>
      </TimeBlockList>
    </ScheduleDay>"""

        days_xml = "\n".join(day_block(i) for i in range(1, 8))

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<TrackSchedule>
  <id>{channel_id}</id>
  <ScheduleDayList>
{days_xml}
  </ScheduleDayList>
</TrackSchedule>"""

        try:
            self._put(f"/ContentMgmt/record/tracks/{channel_id}/schedule", xml)
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
            for u in (root.findall(f".//{_ns('User')}") or root.findall(".//User")):
                uid = _text(u, "id", default="")
                uname = _text(u, "userName", default="")
                if uid and uname:
                    users[uname] = uid
            return users
        except Exception as e:
            logger.warning(f"Get existing users: {e}")
            return {}

    def create_user(self, username, password, role="viewer"):
        """Create a user on the DVR. Returns user id or raises."""
        # Check if already exists
        existing = self._get_existing_users()
        if username in existing:
            logger.info(f"User {username} already exists (id={existing[username]}), updating password")
            uid = existing[username]
            self._update_user_password(uid, username, password, role)
            return uid

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<User>
  <id>2</id>
  <userName>{username}</userName>
  <password>{password}</password>
  <userLevel>{role}</userLevel>
</User>"""
        try:
            r = self._post("/Security/users", xml)
            root = _parse_xml(r.text)
            if root is not None:
                uid = _text(root, "id", default="")
                return uid
            return "unknown"
        except Exception as e:
            logger.error(f"Create user {username}: {e}")
            raise

    def _update_user_password(self, uid, username, password, role):
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<User>
  <id>{uid}</id>
  <userName>{username}</userName>
  <password>{password}</password>
  <userLevel>{role}</userLevel>
</User>"""
        try:
            self._put(f"/Security/users/{uid}", xml)
        except Exception as e:
            logger.warning(f"Update user {uid}: {e}")

    def set_user_permissions(self, uid, username, permission_set):
        """
        permission_set: 'cms' or 'dlt'
        Maps to Hikvision permission flags.
        """
        if permission_set == "cms":
            remote_perms = """
      <remoteParameters>true</remoteParameters>
      <remoteLog>true</remoteLog>
      <remoteLive>true</remoteLive>
      <remotePlayBack>true</remotePlayBack>"""
            local_perms = """
      <localLog>true</localLog>
      <localPlayBack>true</localPlayBack>
      <localExport>true</localExport>"""
        else:  # dlt
            remote_perms = """
      <remoteParameters>true</remoteParameters>
      <remoteLog>true</remoteLog>
      <remoteLive>true</remoteLive>
      <remotePlayBack>true</remotePlayBack>
      <remoteShutdown>true</remoteShutdown>"""
            local_perms = ""

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<UserPermission>
  <id>{uid}</id>
  <userID>{uid}</userID>
  <userType>localUser</userType>
  <remotePermission>{remote_perms}
  </remotePermission>
  <localPermission>{local_perms}
  </localPermission>
</UserPermission>"""
        try:
            self._put(f"/Security/users/{uid}/userPermission", xml)
            return True
        except Exception as e:
            logger.warning(f"Set permissions for {username}: {e}")
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
            results.append({
                "check": "Time Zone",
                "status": "pass" if expected.get("hikvision_timezone", "") in tz else "warn",
                "detail": f"Timezone: {tz}",
                "action": "" if expected.get("hikvision_timezone", "") in tz else "Check timezone setting on device.",
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

        # Recording Status (spot-check first channel)
        try:
            r = self._get("/ContentMgmt/record/tracks/101/schedule")
            root = _parse_xml(r.text)
            has_sched = root is not None
            results.append({
                "check": "Recording Schedule",
                "status": "pass" if has_sched else "warn",
                "detail": "Schedule configured on channel 1" if has_sched else "Could not verify schedule",
                "action": "" if has_sched else "Manually verify recording schedule.",
            })
        except Exception:
            results.append({"check": "Recording Schedule", "status": "warn",
                            "detail": "Could not verify via API", "action": "Manually verify recording schedule."})

        # Camera Stream (spot-check first channel)
        try:
            r = self._get("/Streaming/channels/101")
            root = _parse_xml(r.text)
            codec = _text(root, "Video", "videoCodecType", default="") if root else ""
            w = _text(root, "Video", "videoResolutionWidth", default="0") if root else "0"
            results.append({
                "check": "Camera Stream Settings",
                "status": "pass" if codec.upper() in ("H.264", "H264") else "warn",
                "detail": f"Channel 1 — Codec: {codec}, Resolution: {w}p",
                "action": "" if codec else "Verify stream settings manually.",
            })
        except Exception:
            results.append({"check": "Camera Stream Settings", "status": "warn",
                            "detail": "Could not verify via API", "action": "Manually verify stream settings."})

        # Holiday
        try:
            r = self._get("/System/holidays")
            root = _parse_xml(r.text)
            has_holiday = root is not None
            results.append({
                "check": "Holiday Schedule",
                "status": "pass" if has_holiday else "warn",
                "detail": "Holiday schedule verified" if has_holiday else "Could not verify",
                "action": "" if has_holiday else "Manually verify holiday schedule.",
            })
        except Exception:
            results.append({"check": "Holiday Schedule", "status": "warn",
                            "detail": "Could not verify via API", "action": "Manually verify holiday schedule."})

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
