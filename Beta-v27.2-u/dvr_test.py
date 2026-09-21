"""
DVR API Diagnostic Tool
=======================
Run this from the shell to directly test user creation against a device.

Usage:
    cd Beta-V27
    python dvr_test.py <ip> <port> <admin_username> <admin_password>

Example:
    python dvr_test.py wz1109-cwjphwqtcz.dynamic-m.com 8086 admin MyPassword

It will:
  1. GET /ISAPI/Security/users  — show the raw device response
  2. Try POST with plain-text password
  3. Try POST with MD5-hashed password
  4. Try PUT /ISAPI/Security/users with full UserList + new user injected
  5. Try PUT /ISAPI/Security/users/<ID> to update existing user
  6. Report which (if any) approach succeeded
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

TEST_USER = "_dvr_diag_test_"
TEST_PASS_PLAIN = "Test@1234"
TEST_PASS_MD5   = hashlib.md5(TEST_PASS_PLAIN.encode()).hexdigest()

auth    = HTTPDigestAuth(ADMIN, PASSWORD)
session = requests.Session()
HEADERS = {"Content-Type": "application/xml"}


def hr(label):
    print(f"\n{'='*70}")
    print(f"  {label}")
    print('='*70)


def do_get(path):
    url = BASE + path
    print(f"GET {url}")
    r = session.get(url, auth=auth, verify=False, timeout=15)
    print(f"Status: {r.status_code}")
    print(f"Body:\n{r.text}")
    return r


def do_post(path, body):
    url = BASE + path
    print(f"POST {url}")
    print(f"Body sent:\n{body}")
    try:
        r = session.post(url, auth=auth, verify=False, timeout=15,
                         data=body, headers=HEADERS)
        print(f"Status: {r.status_code}")
        print(f"Response:\n{r.text}")
        return r
    except Exception as e:
        print(f"ERROR: {e}")
        return None


def do_put(path, body):
    url = BASE + path
    print(f"PUT {url}")
    print(f"Body sent:\n{body}")
    try:
        r = session.put(url, auth=auth, verify=False, timeout=15,
                        data=body, headers=HEADERS)
        print(f"Status: {r.status_code}")
        print(f"Response:\n{r.text}")
        return r
    except Exception as e:
        print(f"ERROR: {e}")
        return None


def cleanup_test_user(uid):
    """Try to delete the test user so we don't leave junk on the device."""
    if not uid:
        return
    url = BASE + f"/Security/users/{uid}"
    try:
        r = session.delete(url, auth=auth, verify=False, timeout=10)
        print(f"Cleanup DELETE /Security/users/{uid} → {r.status_code}")
    except Exception as e:
        print(f"Cleanup failed: {e}")


def extract_ns(xml_text):
    """Extract xmlns from root element, return empty string if none."""
    m = re.search(r'xmlns="([^"]+)"', xml_text)
    return m.group(1) if m else ""


def get_user_id(xml_text, username):
    """Find a user's ID in an XML response."""
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


# ─── STEP 1: GET current user list ──────────────────────────────────────────
hr("STEP 1: GET /ISAPI/Security/users  (show raw device XML)")
r_get = do_get("/Security/users")
raw_userlist = r_get.text if r_get.status_code == 200 else ""
detected_ns = extract_ns(raw_userlist)
print(f"\nDetected xmlns: '{detected_ns}'")


# ─── STEP 2: POST with plain-text password, no xmlns ────────────────────────
hr("STEP 2: POST /ISAPI/Security/users — plain-text password, NO xmlns on <User>")
body_plain_no_ns = f"""<?xml version="1.0" encoding="UTF-8"?>
<User>
  <id>0</id>
  <userName>{TEST_USER}</userName>
  <password>{TEST_PASS_PLAIN}</password>
  <bondIpList>
    <bondIp>
      <id>1</id>
      <ipAddress>0.0.0.0</ipAddress>
      <ipv6Address>::</ipv6Address>
    </bondIp>
  </bondIpList>
  <macAddress></macAddress>
  <userLevel>Viewer</userLevel>
  <attribute>
    <inherent>false</inherent>
  </attribute>
</User>"""
r2 = do_post("/Security/users", body_plain_no_ns)
created_uid = None
if r2 and r2.status_code == 200:
    created_uid = get_user_id(r2.text, TEST_USER) or get_user_id(do_get("/Security/users").text, TEST_USER)
    print(f"✓ SUCCESS! Plain-text no-xmlns POST worked. UID={created_uid}")
    cleanup_test_user(created_uid)
    sys.exit(0)


# ─── STEP 3: POST with MD5-hashed password ──────────────────────────────────
hr(f"STEP 3: POST — MD5-hashed password ({TEST_PASS_MD5}), no xmlns")
body_md5 = f"""<?xml version="1.0" encoding="UTF-8"?>
<User>
  <id>0</id>
  <userName>{TEST_USER}</userName>
  <password>{TEST_PASS_MD5}</password>
  <bondIpList>
    <bondIp>
      <id>1</id>
      <ipAddress>0.0.0.0</ipAddress>
      <ipv6Address>::</ipv6Address>
    </bondIp>
  </bondIpList>
  <macAddress></macAddress>
  <userLevel>Viewer</userLevel>
  <attribute>
    <inherent>false</inherent>
  </attribute>
</User>"""
r3 = do_post("/Security/users", body_md5)
if r3 and r3.status_code == 200:
    created_uid = get_user_id(do_get("/Security/users").text, TEST_USER)
    print(f"✓ SUCCESS! MD5-password POST worked. UID={created_uid}")
    cleanup_test_user(created_uid)
    sys.exit(0)


# ─── STEP 4: POST with xmlns matching device namespace ──────────────────────
if detected_ns:
    hr(f"STEP 4: POST — plain password, xmlns='{detected_ns}'")
    body_ns = f"""<?xml version="1.0" encoding="UTF-8"?>
<User xmlns="{detected_ns}">
  <id>0</id>
  <userName>{TEST_USER}</userName>
  <password>{TEST_PASS_PLAIN}</password>
  <bondIpList>
    <bondIp>
      <id>1</id>
      <ipAddress>0.0.0.0</ipAddress>
      <ipv6Address>::</ipv6Address>
    </bondIp>
  </bondIpList>
  <macAddress></macAddress>
  <userLevel>Viewer</userLevel>
  <attribute>
    <inherent>false</inherent>
  </attribute>
</User>"""
    r4 = do_post("/Security/users", body_ns)
    if r4 and r4.status_code == 200:
        created_uid = get_user_id(do_get("/Security/users").text, TEST_USER)
        print(f"✓ SUCCESS! Plain+xmlns POST worked. UID={created_uid}")
        cleanup_test_user(created_uid)
        sys.exit(0)


# ─── STEP 5: GET-then-clone single User + POST ──────────────────────────────
hr("STEP 5: POST — clone first <User> block from GET response and patch it")
if raw_userlist:
    m = re.search(
        r'<(?:[^:>\s/]+:)?User(?:\s[^>]*)?>.*?</(?:[^:>\s/]+:)?User>',
        raw_userlist, re.DOTALL
    )
    if m:
        cloned = m.group(0)
        # Patch fields
        for tag, val in [('id','0'), ('userName',TEST_USER), ('password',TEST_PASS_PLAIN),
                          ('userLevel','Viewer'), ('inherent','false')]:
            cloned = re.sub(
                rf'(<(?:[^:>\s/]+:)?{re.escape(tag)}(?:\s[^>]*)?>).*?(</(?:[^:>\s/]+:)?{re.escape(tag)}>)',
                rf'\g<1>{val}\g<2>', cloned, flags=re.DOTALL
            )
        body_clone = '<?xml version="1.0" encoding="UTF-8"?>\n' + cloned
        r5 = do_post("/Security/users", body_clone)
        if r5 and r5.status_code == 200:
            created_uid = get_user_id(do_get("/Security/users").text, TEST_USER)
            print(f"✓ SUCCESS! Clone+POST worked. UID={created_uid}")
            cleanup_test_user(created_uid)
            sys.exit(0)
    else:
        print("No <User> block found in GET response — skipping clone test")


# ─── STEP 6: PUT full UserList with new user injected ───────────────────────
hr("STEP 6: PUT /ISAPI/Security/users — inject new <User> into full UserList")
if raw_userlist:
    new_block = f"""  <User>
    <id>0</id>
    <userName>{TEST_USER}</userName>
    <password>{TEST_PASS_PLAIN}</password>
    <bondIpList>
      <bondIp>
        <id>1</id>
        <ipAddress>0.0.0.0</ipAddress>
        <ipv6Address>::</ipv6Address>
      </bondIp>
    </bondIpList>
    <macAddress></macAddress>
    <userLevel>Viewer</userLevel>
    <attribute>
      <inherent>false</inherent>
    </attribute>
  </User>"""
    modified, n = re.subn(
        r'(</(?:[^:>\s/]+:)?UserList>)',
        new_block + r'\n\1',
        raw_userlist
    )
    if n == 0:
        print("Could not find </UserList> tag — trying </userList>")
        modified, n = re.subn(r'(</(?:[^:>\s/]+:)?[Uu]ser[Ll]ist>)', new_block + r'\n\1', raw_userlist)
    r6 = do_put("/Security/users", modified)
    if r6 and r6.status_code in (200, 204):
        created_uid = get_user_id(do_get("/Security/users").text, TEST_USER)
        if created_uid:
            print(f"✓ SUCCESS! PUT-UserList worked. UID={created_uid}")
            cleanup_test_user(created_uid)
            sys.exit(0)
        else:
            print("PUT returned 200 but user not found in refreshed list")


# ─── STEP 7: PUT full UserList with MD5 password ────────────────────────────
hr("STEP 7: PUT /ISAPI/Security/users — inject new <User> with MD5 password")
if raw_userlist:
    new_block_md5 = new_block.replace(TEST_PASS_PLAIN, TEST_PASS_MD5)
    modified_md5, n = re.subn(
        r'(</(?:[^:>\s/]+:)?[Uu]ser[Ll]ist>)',
        new_block_md5 + r'\n\1',
        raw_userlist
    )
    r7 = do_put("/Security/users", modified_md5)
    if r7 and r7.status_code in (200, 204):
        created_uid = get_user_id(do_get("/Security/users").text, TEST_USER)
        if created_uid:
            print(f"✓ SUCCESS! PUT-UserList+MD5 worked. UID={created_uid}")
            cleanup_test_user(created_uid)
            sys.exit(0)
        else:
            print("PUT+MD5 returned 200 but user not found in refreshed list")


# ─── Summary ─────────────────────────────────────────────────────────────────
hr("RESULT: All approaches failed")
print("The device rejected every method tried above.")
print("Review the raw responses above — especially the GET /Security/users")
print("output (Step 1) which shows the exact structure the device uses.")
print("\nPossible next steps:")
print("  - Check if the device web UI allows API user management")
print("  - Check if a ?security=1 encrypted-password mode is required")
print("  - Check if the device firmware version supports user creation via ISAPI")
sys.exit(1)
