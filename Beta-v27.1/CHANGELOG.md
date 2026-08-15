# AZ Sentinel X — Changelog

---

## Beta-v26 — July 2026

### 🆕 New Features

#### DVR/NVR Configuration Management — Navigation Overhaul
- All DVR-related modules are now grouped under a single collapsible **DVR/NVR Config Mgmt** section in the sidebar
- Sidebar group auto-expands when you are on any DVR page
- New tree structure:
  - Single Device Configuration
  - Bulk Device Configuration
  - Camera Names Configuration
  - Configuration Templates *(new standalone page)*
  - Reports *(new standalone page)*
  - Configuration History *(new standalone page)*

#### Configuration History Page (`/dvr/history`)
- Standalone audit log of all single-device configuration sessions
- Search/filter by device name, IP, technician, or overall result
- Session count display
- Pass / Warning / Failed check counts per session
- **View** button opens a full Session Audit Log modal showing:
  - Device info header with overall badge
  - Complete validation results table
  - Stream configuration per channel (with fallback notes)
  - User accounts created

#### Reports Page (`/dvr/reports`)
- Summary scorecards: Total Sessions / Passed / Failed+Warning
- Session list with one-click download buttons (PDF, Excel, JSON)
- Email modal per session with format selection

#### Configuration Templates Page (`/dvr/templates`)
- Three built-in profiles: Retail Standard, Corporate Office, Warehouse/Industrial
- Preview modal showing full stream/recording/user details per template
- "Create Template from Session" modal (saves completed sessions as reusable profiles)

#### Step 10 — Professional Configuration Report
- Replaced plain completion message with a full professional report view:
  - **Device header** — Name, IP/port, Model, Firmware, Serial, MAC, Channels, Technician, Timestamp
  - **Score scorecards** — Passed / Warnings / Failed check counts
  - **Configuration Steps summary** — Time/NTP, Storage, Streams, Recording, Holiday, Users with inline details
  - **Validation Checks table** — Full pass/warn/fail with action hints
  - **User Accounts section** — All accounts created with credentials
  - **Overall badge** (PASS / WARNING / FAIL) in the card header

### 🔧 Improvements

#### Sub-Stream "Fallback" Resolution — False Failure Fix
- `configure_sub_stream()` previously marked sub-stream as **Failed** when the primary resolution (960×576) was not supported by the device
- Now uses an intelligent fallback chain: `960×576 → 960×540 → 704×576 → 704×480 → 640×480`
- Status values:
  - `configured` — primary resolution applied ✅
  - `configured_fallback` — alternative resolution applied (shown as amber warning with note) ⚠
  - `error` — all resolutions rejected (genuine failure) ❌
- Fallback note displayed in Step 5 stream table and the Step 10 report

#### Session History — Enhanced Columns
- History modal now shows: Device, IP, **Checks** (✅/⚠/❌ counts), Overall, Technician, Date, **Audit Log (View button)**
- Replaced flat 5-column table with full 7-column audit view
- Sessions API (`/api/dvr/sessions`) now returns `passed`, `warned`, `failed` counts per session

#### Badge Helper — New Status Styles
- `configured_fallback` → amber warning badge labelled "fallback"
- `skipped` → grey neutral badge
- `created_permissions_failed` → amber warning badge

### 🔒 Security

#### DPCM Role (Replaces DVR Technician & Support Agent)
- Removed the `dvr_technician` (DVR Technician) and `senior_dvr_technician` (Support Agent) roles
- New single role: **DPCM** — full access to DVR/NVR Configuration Management only
- DPCM permissions: `dvr_config` + `dvr_bulk`; **zero access** to Dashboard, Alerts, Reports, Threat Intel, or any other module
- DPCM users land directly on the DVR Config page after login
- **Automatic DB migration** on app startup renames any existing accounts with the old roles to `dpcm`
- User creation/edit UI updated to show DPCM only

#### URL Access Control — DVR Modules Now Fully Protected
- The `dvr_config` and `dvr_bulk` blueprints were the only modules **without** a `before_request` permission guard
- Both now enforce `make_blueprint_permission_check` — every other module already had this in place
- Effect: any attempt to visit `/dvr-config`, `/dvr-bulk`, `/dvr/history`, `/dvr/templates`, `/dvr/reports`, or any API endpoint under those blueprints without the correct permission returns:
  - **Unauthenticated** → redirect to login
  - **Wrong role** → Access Denied page (HTTP 403)
  - **API call** → `{"error": "Access denied"}` JSON 403

---

## Beta-v25 — Prior Release

### Features in this version
- 10-step guided DVR/NVR single-device configuration wizard (Hikvision / Platinum / LTS)
- Bulk DVR/NVR configuration via CSV/Excel upload
- Camera Name Management tool
- Timezone configuration with ISAPI `PUT /System/time/timeZone` as primary method
- NTP server and DST configuration
- HDD storage discovery and format
- Main + Sub stream configuration
- Recording schedule (24/7 and motion)
- Holiday schedule (Thanksgiving & Black Friday)
- User account creation: `admin`, `cms_user` (CMS), `manager`, `viewer`
- Step-by-step validation (12 checks) with PASS / WARNING / FAIL overall result
- PDF / Excel / JSON report generation and email delivery
- SOC Analyst, Viewer, Administrator roles
- Alert management with scheduled checks
- AI Insights and Threat Intelligence modules
- Configuration Assessment module
- Storage Management and Data Retention
- Integrations hub
- Console Logs viewer
- Dark-mode responsive UI

---

## Notes

- Directory name remains `Beta-V25/` — this is the application root and is not renamed between versions
- Version badge shown on the login page reflects the current release
- All DVR configuration sessions are persisted in PostgreSQL and accessible via the Configuration History page
