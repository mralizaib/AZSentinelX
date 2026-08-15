"""
DVR API Diagnostic Tool — Full Firmware Compatibility Test
===========================================================
Run this from the shell to test user creation AND recording schedule
against a device.  Covers both plain-text and MD5-password modes so you
can identify whether the device runs firmware < 4.83 (plain) or >= 4.83
(MD5 required).

Usage:
    cd Beta-V27
    python dvr_test.py <ip> <port> <admin_username> <admin_password>

Example:
    python dvr_test.py 192.168.1.64 80 admin Admin@1234

Tests performed:
  USER CREATION (6 methods — plain text + MD5, POST + PUT-list):
    1. GET /Security/users       — show raw device XML & detect format
    2. POST plain text, no xmlns
    3. POST MD5 password, no xmlns
    4. POST plain+xmlns matching device namespace
    5. POST clone existing user + plain password
    6. POST clone existing user + MD5 password
    7. PUT-list inject new user + plain password
    8. PUT-list inject new user + MD5 password

  RECORDING SCHEDULE:
    9. GET /ContentMgmt/record/tracks/101 — show raw XML & detect format
   10. Identify TrackSchedule tag prefix (none / std: / hik:)
   11. Attempt PUT with patched TrackSchedule
"""
import hashlib
import re
import sys
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPDigestAuth

requests.packages.urllib3.disable_warnings()

# ─── Args ───────────────────────────────────────────────────────────────────
if len(sys.argv) < 5:
    print(__doc__)
    sys.exit(1)

IP       = sys.argv[1]
PORT     = int(sys.argv[2])
ADMIN    = sys.argv[3]
PASSWORD = sys.argv[4]
BASE     = f"http://{IP}:{PORT}/ISAPI"

TEST_USER       = "_dvr_diag_test_"
TEST_PASS_PLAIN = "Test@1234"
TEST_PASS_MD5   = hashlib.md5(TEST_PASS_PLAIN.encode()).hexdigest()

auth    = HTTPDigestAuth(ADMIN, PASSWORD)
sess    = requests.Session()
HEADERS = {"Content-Type": "application/xml"}


def hr(label):
    print(f"\n{'='*70}")
    print(f"  {label}")
    print('='*70)


def do_get(path, silent=False):
    url = BASE + path
    if not silent:
        print(f"GET {url}")
    r = sess.get(url, auth=auth, verify=False, timeout=15)
    if not silent:
        print(f"Status: {r.status_code}")
        print(f"Body:\n{r.text[:3000]}")
    return r


def do_post(path, body):
    url = BASE + path
    print(f"POST {url}")
    print(f"Body sent:\n{body}")
    try:
        r = sess.post(url, auth=auth, verify=False, timeout=15,
                      data=body, headers=HEADERS)
        print(f"Status: {r.status_code}")
        print(f"Response:\n{r.text}")
        return r
    except Exception as e:
        print(f"ERROR: {e}")
        return None


def do_put(path, body, silent=False):
    url = BASE + path
    if not silent:
        print(f"PUT {url}")
        print(f"Body sent (first 1000 chars):\n{body[:1000]}")
    try:
        r = sess.put(url, auth=auth, verify=False, timeout=15,
                     data=body, headers=HEADERS)
        if not silent:
            print(f"Status: {r.status_code}")
            print(f"Response:\n{r.text}")
        return r
    except Exception as e:
        if not silent:
            print(f"ERROR: {e}")
        return None


def cleanup_test_user(uid):
    if not uid:
        return
    url = BASE + f"/Security/users/{uid}"
    try:
        r = sess.delete(url, auth=auth, verify=False, timeout=10)
        print(f"Cleanup DELETE /Security/users/{uid} → {r.status_code}")
    except Exception as e:
        print(f"Cleanup failed: {e}")


def extract_ns(xml_text):
    m = re.search(r'xmlns="([^"]+)"', xml_text)
    return m.group(1) if m else ""


def get_user_id(xml_text, username):
    try:
        root = ET.fromstring(xml_text)
        for u in root.iter():
            if u.tag.endswith("User"):
                uid, uname = None, None
                for child in u:
                    tag = child.tag.rsplit('}', 1)[-1]
                    if tag == "id":
                        uid = child.text
                    elif tag == "userName":
                        uname = child.text
                if uname == username and uid:
                    return uid
    except Exception:
        pass
    return None


def detect_bond_ip_format(raw_userlist):
    """Detect which bond-IP element names this firmware uses."""
    if 'bondIpList' in raw_userlist and 'bondIpAddressList' not in raw_userlist:
        return 'bondIpList', 'bondIp'
    return 'bondIpAddressList', 'bondIpAddress'


def build_user_xml(next_id, username, password, use_ns="", list_tag="bondIpAddressList", ip_tag="bondIpAddress"):
    ns_attr = f' xmlns="{use_ns}"' if use_ns else ""
    return (
        f'<User{ns_attr}>\n'
        f'  <id>{next_id}</id>\n'
        f'  <userName>{username}</userName>\n'
        f'  <password>{password}</password>\n'
        f'  <{list_tag}>\n'
        f'    <{ip_tag}>\n'
        f'      <id>1</id>\n'
        f'      <ipAddress>0.0.0.0</ipAddress>\n'
        f'    </{ip_tag}>\n'
        f'  </{list_tag}>\n'
        f'  <userLevel>Viewer</userLevel>\n'
        f'  <attribute>\n'
        f'    <inherent>false</inherent>\n'
        f'  </attribute>\n'
        f'</User>'
    )


def clone_user_xml(raw_userlist, next_id, username, password):
    """Clone first user from GET response and patch fields."""
    m = re.search(
        r'<(?:[^:>\s/]+:)?User(?:\s[^>]*)?>.*?</(?:[^:>\s/]+:)?User>',
        raw_userlist, re.DOTALL
    )
    if not m:
        return None
    cloned = m.group(0)
    for tag, val in [('id', str(next_id)), ('userName', username),
                     ('userLevel', 'Viewer'), ('inherent', 'false')]:
        cloned = re.sub(
            rf'(<(?:[^:>\s/]+:)?{re.escape(tag)}(?:\s[^>]*)?>).*?(</(?:[^:>\s/]+:)?{re.escape(tag)}>)',
            rf'\g<1>{val}\g<2>', cloned, flags=re.DOTALL
        )
    # Remove existing password, inject fresh one
    cloned = re.sub(
        r'<(?:[^:>\s/]+:)?password(?:\s[^>]*)?>.*?</(?:[^:>\s/]+:)?password>',
        '', cloned, flags=re.DOTALL
    )
    cloned = re.sub(
        r'(</(?:[^:>\s/]+:)?User>)',
        f'<password>{password}</password>\n\\1',
        cloned, count=1
    )
    return cloned


# ═══════════════════════════════════════════════════════════════════════════
# SECTION A: User Management
# ═══════════════════════════════════════════════════════════════════════════

hr("STEP 1: GET /ISAPI/Security/users  (show raw device XML & detect format)")
r_get = do_get("/Security/users")
raw_userlist = r_get.text if r_get.status_code == 200 else ""
detected_ns  = extract_ns(raw_userlist)
list_tag, ip_tag = detect_bond_ip_format(raw_userlist)

print(f"\nDetected xmlns:          '{detected_ns}'")
print(f"Detected bondIp format:  <{list_tag}> / <{ip_tag}>")

# Determine next free user slot (avoid slot 0 which is out-of-spec)
used_ids = set()
try:
    root_tmp = ET.fromstring(raw_userlist)
    for u in root_tmp.iter():
        if u.tag.endswith("User"):
            for child in u:
                if child.tag.endswith("id") and child.text:
                    try:
                        used_ids.add(int(child.text))
                    except ValueError:
                        pass
except Exception:
    pass
next_id = next((i for i in range(1, 17) if i not in used_ids), 2)
print(f"Used user slots:         {sorted(used_ids)}")
print(f"Next free slot:          {next_id}")

created_uid = None

# ─── STEP 2: POST plain text, no xmlns, auto-detected element names ────────
hr(f"STEP 2: POST plain-text password, NO xmlns  (bondIp format: {list_tag})")
body_plain = build_user_xml(next_id, TEST_USER, TEST_PASS_PLAIN, list_tag=list_tag, ip_tag=ip_tag)
r2 = do_post("/Security/users", body_plain)
if r2 and r2.status_code == 200:
    created_uid = get_user_id(r2.text, TEST_USER) or get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
    print(f"\n✅ SUCCESS: Plain-text POST worked. UID={created_uid}")
    cleanup_test_user(created_uid)
    sys.exit(0)

# ─── STEP 3: POST MD5 password (required by 4.83+ firmware) ───────────────
hr(f"STEP 3: POST MD5 password [{TEST_PASS_MD5}]  (4.83+ firmware mode)")
body_md5 = build_user_xml(next_id, TEST_USER, TEST_PASS_MD5, list_tag=list_tag, ip_tag=ip_tag)
r3 = do_post("/Security/users", body_md5)
if r3 and r3.status_code == 200:
    created_uid = get_user_id(r3.text, TEST_USER) or get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
    print(f"\n✅ SUCCESS: MD5 POST worked (4.83+ firmware). UID={created_uid}")
    print("   ⚠  ACTION REQUIRED: The main dvr_api.py needs MD5 password support for this device.")
    cleanup_test_user(created_uid)
    sys.exit(0)

# ─── STEP 4: POST plain+xmlns ──────────────────────────────────────────────
if detected_ns:
    hr(f"STEP 4: POST plain password, xmlns='{detected_ns}'")
    body_ns = build_user_xml(next_id, TEST_USER, TEST_PASS_PLAIN, use_ns=detected_ns, list_tag=list_tag, ip_tag=ip_tag)
    r4 = do_post("/Security/users", body_ns)
    if r4 and r4.status_code == 200:
        created_uid = get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
        print(f"\n✅ SUCCESS: plain+xmlns POST worked. UID={created_uid}")
        cleanup_test_user(created_uid)
        sys.exit(0)

# ─── STEP 5: POST clone existing user + plain password ─────────────────────
hr("STEP 5: POST — clone first <User> from GET response, plain password")
if raw_userlist:
    cloned_plain = clone_user_xml(raw_userlist, next_id, TEST_USER, TEST_PASS_PLAIN)
    if cloned_plain:
        r5 = do_post("/Security/users", cloned_plain)
        if r5 and r5.status_code == 200:
            created_uid = get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
            print(f"\n✅ SUCCESS: Clone+plain POST worked. UID={created_uid}")
            cleanup_test_user(created_uid)
            sys.exit(0)
    else:
        print("No <User> block found in GET response — skipping clone step")

# ─── STEP 6: POST clone + MD5 password ────────────────────────────────────
hr("STEP 6: POST — clone first <User> from GET response, MD5 password  (4.83+)")
if raw_userlist:
    cloned_md5 = clone_user_xml(raw_userlist, next_id, TEST_USER, TEST_PASS_MD5)
    if cloned_md5:
        r6 = do_post("/Security/users", cloned_md5)
        if r6 and r6.status_code == 200:
            created_uid = get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
            print(f"\n✅ SUCCESS: Clone+MD5 POST worked (4.83+ firmware). UID={created_uid}")
            print("   ⚠  ACTION: MD5 password support confirmed needed for 4.83+ firmware.")
            cleanup_test_user(created_uid)
            sys.exit(0)

# ─── STEP 7: PUT full UserList + plain password ────────────────────────────
hr("STEP 7: PUT /ISAPI/Security/users — inject new <User>, plain password")
if raw_userlist:
    new_block_plain = (
        f'  <User>\n'
        f'    <id>{next_id}</id>\n'
        f'    <userName>{TEST_USER}</userName>\n'
        f'    <password>{TEST_PASS_PLAIN}</password>\n'
        f'    <{list_tag}>\n'
        f'      <{ip_tag}>\n'
        f'        <id>1</id>\n'
        f'        <ipAddress>0.0.0.0</ipAddress>\n'
        f'      </{ip_tag}>\n'
        f'    </{list_tag}>\n'
        f'    <userLevel>Viewer</userLevel>\n'
        f'    <attribute><inherent>false</inherent></attribute>\n'
        f'  </User>'
    )
    modified, n = re.subn(
        r'(</(?:[^:>\s/]+:)?[Uu]ser[Ll]ist>)',
        new_block_plain + r'\n\1',
        raw_userlist
    )
    r7 = do_put("/Security/users", modified)
    if r7 and r7.status_code in (200, 204):
        created_uid = get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
        if created_uid:
            print(f"\n✅ SUCCESS: PUT-list plain worked. UID={created_uid}")
            cleanup_test_user(created_uid)
            sys.exit(0)
        else:
            print("PUT returned 200 but user not found in refreshed list")

# ─── STEP 8: PUT full UserList + MD5 password ─────────────────────────────
hr("STEP 8: PUT /ISAPI/Security/users — inject new <User>, MD5 password  (4.83+)")
if raw_userlist:
    new_block_md5 = new_block_plain.replace(TEST_PASS_PLAIN, TEST_PASS_MD5)
    modified_md5, n = re.subn(
        r'(</(?:[^:>\s/]+:)?[Uu]ser[Ll]ist>)',
        new_block_md5 + r'\n\1',
        raw_userlist
    )
    r8 = do_put("/Security/users", modified_md5)
    if r8 and r8.status_code in (200, 204):
        created_uid = get_user_id(do_get("/Security/users", silent=True).text, TEST_USER)
        if created_uid:
            print(f"\n✅ SUCCESS: PUT-list MD5 worked (4.83+ firmware). UID={created_uid}")
            print("   ⚠  ACTION: MD5 password support confirmed needed for 4.83+ firmware.")
            cleanup_test_user(created_uid)
            sys.exit(0)
        else:
            print("PUT+MD5 returned 200 but user not found in refreshed list")

# ═══════════════════════════════════════════════════════════════════════════
# SECTION B: Recording Schedule Diagnosis
# ═══════════════════════════════════════════════════════════════════════════

hr("STEP 9: GET /ContentMgmt/record/tracks/101 — recording schedule XML format")
r_track = do_get("/ContentMgmt/record/tracks/101")
track_xml = r_track.text if r_track.status_code == 200 else ""

if track_xml:
    # Detect TrackSchedule tag prefix
    ts_match = re.search(
        r'<((?:[^:>\s/]+:)?TrackSchedule)(?:\s[^>]*)?>',
        track_xml
    )
    if ts_match:
        ts_tag = ts_match.group(1)
        print(f"\n📋 TrackSchedule tag found: <{ts_tag}>")
        print("   Schedule block content:")
        block = re.search(
            r'<(?:[^:>\s/]+:)?TrackSchedule(?:\s[^>]*)?>.*?</(?:[^:>\s/]+:)?TrackSchedule>',
            track_xml, re.DOTALL
        )
        if block:
            print(block.group(0)[:2000])
    else:
        print("\n⚠  No <TrackSchedule> tag found in track XML.")
        print("   The recording schedule may use a different structure on this firmware.")

    # Try a simple PUT with a patched TrackSchedule
    hr("STEP 10: Try PUT with patched TrackSchedule (namespace-aware)")
    WEEK = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    def _make_action(aid, sd, st, ed, et, mode):
        return (f"<ScheduleAction><id>{aid}</id>"
                f"<ScheduleActionStartTime><DayOfWeek>{sd}</DayOfWeek><TimeOfDay>{st}</TimeOfDay></ScheduleActionStartTime>"
                f"<ScheduleActionEndTime><DayOfWeek>{ed}</DayOfWeek><TimeOfDay>{et}</TimeOfDay></ScheduleActionEndTime>"
                f"<ScheduleDSTEnable>false</ScheduleDSTEnable><Description>nothing</Description>"
                f"<Actions><Record>true</Record><Log>false</Log><SaveImg>false</SaveImg>"
                f"<ActionRecordingMode>{mode}</ActionRecordingMode></Actions></ScheduleAction>")

    def _make_block(guid_sfx, mode, start, end):
        acts = []
        for i, day in enumerate(WEEK):
            nd = WEEK[(i + 1) % 7]
            ed = nd if end == "00:00:00" else day
            acts.append(_make_action(i + 1, day, start, ed, end, mode))
        return (f"<ScheduleBlock>"
                f"<ScheduleBlockGUID>{{0000000{guid_sfx}-0000-0000-0000-000000000000}}</ScheduleBlockGUID>"
                f"<ScheduleBlockType>www.std-cgi.com/racm/schedule/ver10</ScheduleBlockType>"
                + "".join(acts) + "</ScheduleBlock>")

    new_ts = ("<TrackSchedule><ScheduleBlockList>"
              + _make_block("0", "MOTION", "00:00:00", "08:00:00")
              + _make_block("1", "CMR", "08:00:00", "22:00:00")
              + _make_block("2", "MOTION", "22:00:00", "00:00:00")
              + "</ScheduleBlockList></TrackSchedule>")

    # Namespace-aware replacement
    ts_re = re.compile(
        r'<(?:[^:>\s/]+:)?TrackSchedule(?:\s[^>]*)?>.*?</(?:[^:>\s/]+:)?TrackSchedule>',
        re.DOTALL
    )
    ts_hit = ts_re.search(track_xml)
    if ts_hit:
        updated_track = track_xml[:ts_hit.start()] + new_ts + track_xml[ts_hit.end():]
    else:
        updated_track = re.sub(
            r'(</(?:[^:>\s/]+:)?Track>)',
            new_ts + r'\n\1',
            track_xml, count=1
        )

    r_put_track = do_put("/ContentMgmt/record/tracks/101", updated_track)
    if r_put_track and r_put_track.status_code in (200, 204):
        print(f"\n✅ SUCCESS: Recording schedule PUT worked on channel 101.")
    elif r_put_track:
        print(f"\n❌ Recording schedule PUT failed: HTTP {r_put_track.status_code}")
        print(f"   Response: {r_put_track.text[:500]}")
else:
    print("Could not retrieve track XML (HTTP {}) — endpoint may not exist on this firmware.".format(
        r_track.status_code))

# ─── Summary ──────────────────────────────────────────────────────────────
hr("RESULT: All user-creation approaches failed")
print("The device rejected every user-creation method.")
print("\nDiagnostic summary:")
print(f"  xmlns detected:      {detected_ns or '(none)'}")
print(f"  bondIp format:       <{list_tag}> / <{ip_tag}>")
print(f"  Firmware hint:       if MD5 steps failed too, check HTTPS requirement or admin lock")
print("\nNext steps:")
print("  - Check firmware version via device web UI → System → Device Info")
print("  - If firmware >= 4.83: ensure MD5 password mode is what the device requires")
print("  - Check if device has 'Illegal Login Protection' active (lock-out timer)")
print("  - Check if HTTPS is required (rerun with 'https' in BASE url)")
sys.exit(1)
