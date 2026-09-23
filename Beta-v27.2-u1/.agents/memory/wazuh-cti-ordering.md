---
name: Wazuh CTI aggregation ordering
description: The Wazuh CTI fetch aggregation must sort CVE buckets by most-recent detection timestamp, not by document count.
---

## Rule
In `fetch_wazuh_cti`, the `unique_cves` terms aggregation must use `"order": {"max_date": "desc"}` with a `"max_date": {"max": {"field": "@timestamp"}}` sub-agg. Never use `"order": {"_count": "desc"}`.

**Why:** Wazuh scans endpoints repeatedly. A CVE first detected a year ago accumulates thousands of alert documents and always wins a count-based sort. Newly-detected CVEs (from today's scan) have only 1-2 documents and fall outside the 200-bucket limit, so they are never imported — even though they are exactly what the analyst wants to see.

**How to apply:** Any time you modify `_build_agg_query` in `threat_intel_service.py`, keep the `max_date` sub-agg and its use in `order`. Do not simplify it away.

## Related: wazuh_cti upsert
`store_new_items` must do a true upsert for `source == 'wazuh_cti'` items: refresh `description`, `severity`, `has_patch`, `has_mitigation`, and `fetched_at` for existing GUIDs. The description contains the `[WAZUH_ACTIVE_AGENTS:...]` / `[WAZUH_SOLVED_AGENTS:...]` blobs used by the correlator — if not refreshed, agent lists go stale as vulnerabilities are patched.
