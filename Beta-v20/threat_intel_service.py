"""
Threat Intelligence Service for ByteIT SentinelX
Monitors cybersecurity news, CVEs, and advisories.
Analyses relevance with AI and sends email alerts.
"""
import logging
import hashlib
import re
import json
import requests
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

logger = logging.getLogger(__name__)

FEED_SOURCES = {
    'cisa_kev': {
        'name': 'CISA Known Exploited Vulnerabilities',
        'type': 'json_api',
        'url': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'icon': 'shield-alt',
        'color': 'danger',
    },
    'cisa_alerts': {
        'name': 'CISA Cybersecurity Advisories',
        'type': 'rss',
        'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'icon': 'flag',
        'color': 'warning',
    },
    'nvd': {
        'name': 'NVD – Recent CVEs',
        'type': 'nvd_api',
        'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'icon': 'database',
        'color': 'info',
    },
    'wazuh_cti': {
        'name': 'Wazuh CTI – Vulnerability Detections',
        'type': 'wazuh_cti',
        'url': 'https://cti.wazuh.com/vulnerabilities/cves',
        'icon': 'shield-virus',
        'color': 'danger',
        'description': 'CVE vulnerability data detected by your Wazuh agents, sourced from the Wazuh CTI database.',
    },
    'bleepingcomputer': {
        'name': 'Bleeping Computer',
        'type': 'rss',
        'url': 'https://www.bleepingcomputer.com/feed/',
        'icon': 'newspaper',
        'color': 'primary',
    },
    'hackernews': {
        'name': 'The Hacker News',
        'type': 'rss',
        'url': 'https://feeds.feedburner.com/TheHackersNews',
        'icon': 'bug',
        'color': 'secondary',
    },
    'securityweek': {
        'name': 'SecurityWeek',
        'type': 'rss',
        'url': 'https://feeds.feedburner.com/Securityweek',
        'icon': 'globe',
        'color': 'success',
    },
}

PATCH_KEYWORDS = [
    'patch', 'update', 'fix', 'hotfix', 'security update', 'advisory',
    'mitigation', 'workaround', 'remediation', 'upgrade', 'released',
    'available', 'cve-', 'vulnerability patched',
]
MITIGATION_KEYWORDS = [
    'mitigation', 'workaround', 'disable', 'restrict', 'block',
    'firewall rule', 'isolate', 'configuration change',
]
SEVERITY_KEYWORDS = {
    'critical': ['critical', 'zero-day', '0-day', 'ransomware', 'actively exploited', 'worm'],
    'high': ['high severity', 'remote code execution', 'rce', 'privilege escalation', 'authentication bypass'],
    'medium': ['medium severity', 'denial of service', 'dos', 'information disclosure', 'xss'],
    'low': ['low severity', 'minor', 'informational'],
}


def _make_guid(source_key: str, identifier: str) -> str:
    return hashlib.sha256(f"{source_key}:{identifier}".encode()).hexdigest()[:64]


def _detect_severity(text: str) -> str:
    text_lower = text.lower()
    for sev, kws in SEVERITY_KEYWORDS.items():
        if any(kw in text_lower for kw in kws):
            return sev
    return 'unknown'


def _detect_patch(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in PATCH_KEYWORDS)


def _detect_mitigation(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in MITIGATION_KEYWORDS)


def _extract_cves(text: str) -> list:
    return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))


def _parse_date(date_str) -> datetime:
    if not date_str:
        return datetime.utcnow()
    if hasattr(date_str, 'timetuple'):
        return datetime(*date_str.timetuple()[:6])
    fmts = ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d', '%m/%d/%Y']
    for fmt in fmts:
        try:
            return datetime.strptime(str(date_str)[:26], fmt)
        except (ValueError, TypeError):
            pass
    return datetime.utcnow()


def fetch_cisa_kev(limit=50) -> list:
    """Fetch CISA Known Exploited Vulnerabilities catalogue."""
    items = []
    try:
        resp = requests.get(FEED_SOURCES['cisa_kev']['url'], timeout=15)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get('vulnerabilities', [])[:limit]
        for v in vulns:
            cve_id = v.get('cveID', '')
            title = f"{cve_id}: {v.get('vulnerabilityName', 'Unknown')}"
            desc = (f"Product: {v.get('product', 'N/A')} | Vendor: {v.get('vendorProject', 'N/A')} | "
                    f"Action: {v.get('requiredAction', 'N/A')} | Due: {v.get('dueDate', 'N/A')}")
            guid = _make_guid('cisa_kev', cve_id)
            published = _parse_date(v.get('dateAdded', ''))
            cves = [cve_id] if cve_id else []
            items.append({
                'guid': guid,
                'title': title,
                'description': desc,
                'url': f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                'source': 'cisa_kev',
                'published_at': published,
                'severity': 'critical',
                'has_patch': True,
                'has_mitigation': True,
                'cve_ids': cves,
            })
    except Exception as e:
        logger.error(f"Error fetching CISA KEV: {e}")
    return items


def fetch_nvd(days_back=1, limit=20) -> list:
    """Fetch recent CVEs from NVD API v2."""
    items = []
    try:
        from datetime import timedelta
        end = datetime.utcnow()
        start = end - timedelta(days=days_back)
        params = {
            'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': limit,
        }
        resp = requests.get(FEED_SOURCES['nvd']['url'], params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            descriptions = cve.get('descriptions', [])
            eng_desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics:
                    try:
                        cvss_score = metrics[key][0]['cvssData']['baseScore']
                        break
                    except (KeyError, IndexError):
                        pass
            if cvss_score >= 9.0:
                sev = 'critical'
            elif cvss_score >= 7.0:
                sev = 'high'
            elif cvss_score >= 4.0:
                sev = 'medium'
            else:
                sev = 'low'
            title = f"{cve_id} – CVSS {cvss_score:.1f}"
            guid = _make_guid('nvd', cve_id)
            published = _parse_date(cve.get('published', ''))
            items.append({
                'guid': guid,
                'title': title,
                'description': eng_desc[:1000],
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'source': 'nvd',
                'published_at': published,
                'severity': sev,
                'has_patch': _detect_patch(eng_desc),
                'has_mitigation': _detect_mitigation(eng_desc),
                'cve_ids': [cve_id],
            })
    except Exception as e:
        logger.error(f"Error fetching NVD CVEs: {e}")
    return items


def fetch_rss(source_key: str, limit=20) -> list:
    """Fetch items from an RSS feed."""
    items = []
    src = FEED_SOURCES.get(source_key)
    if not src or src['type'] != 'rss':
        return items
    try:
        try:
            import feedparser
        except ImportError:
            logger.error(
                "feedparser is not installed. Run: pip install feedparser>=6.0.0"
            )
            return items
        feed = feedparser.parse(src['url'])
        for entry in feed.entries[:limit]:
            title = entry.get('title', 'No title')
            desc = entry.get('summary', entry.get('description', ''))
            url = entry.get('link', '')
            guid = _make_guid(source_key, entry.get('id', url or title))
            published = _parse_date(entry.get('published_parsed') or entry.get('updated_parsed'))
            combined = f"{title} {desc}"
            sev = _detect_severity(combined)
            cves = _extract_cves(combined)
            items.append({
                'guid': guid,
                'title': title[:500],
                'description': desc[:2000],
                'url': url,
                'source': source_key,
                'published_at': published,
                'severity': sev,
                'has_patch': _detect_patch(combined),
                'has_mitigation': _detect_mitigation(combined),
                'cve_ids': cves,
            })
    except Exception as e:
        logger.error(f"Error fetching RSS feed {source_key}: {e}")
    return items


def fetch_wazuh_cti(limit=500) -> list:
    """
    Harvest CVE vulnerability detections from Wazuh/OpenSearch that were
    originally sourced from the Wazuh Vulnerability Detector (cti.wazuh.com).
    Uses aggregations to collect unique CVEs across ALL software packages — not
    just the most recently scanned ones — so that all application types are
    represented, not only the latest batch of Chrome/browser alerts.
    """
    items = []
    try:
        from opensearch_api import OpenSearchAPI
        api = OpenSearchAPI()

        if not api.client:
            logger.warning("Wazuh CTI: OpenSearch client not connected, skipping feed")
            return items

        # Use aggregations to get every unique CVE seen across all packages.
        # top_hits gives us the most-recent raw document for each CVE.
        # agents sub-agg lists every agent on which the CVE was detected.
        # data.vulnerability.cve is already a 'keyword' field in Wazuh's mapping
        # — no .keyword suffix required. Same for package.name and agent.name.
        # Agent IPs/locations are enriched later via the inventory DB in the correlator,
        # so we only need a lightweight terms agg here.
        # Instead of static filter sub-aggs (which break when Wazuh uses unexpected
        # capitalisations like "ACTIVE"/"SOLVED" or "Pending confirmation"), we use a
        # per-agent top_hits agg to read each agent's *actual* latest status value and
        # then classify it case-insensitively in Python.  This is robust across all
        # Wazuh versions and index configurations.

        agg_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"rule.groups": "vulnerability-detector"}},
                                    {"term": {"rule.groups": "vulnerability"}},
                                    {"term": {"rule.groups": "vulnerability_detector"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {"exists": {"field": "data.vulnerability.cve"}},
                    ]
                }
            },
            "aggs": {
                "unique_cves": {
                    "terms": {
                        "field": "data.vulnerability.cve",
                        "size": limit,
                        "order": {"_count": "desc"},
                    },
                    "aggs": {
                        # Most recent full vulnerability record for all display fields
                        "top_hit": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": ["data.vulnerability.*", "agent.*", "@timestamp"],
                            }
                        },
                        # Per-agent latest status — captures any value Wazuh may use
                        # (Active, active, ACTIVE, Solved, solved, SOLVED, etc.)
                        # All required structured vulnerability fields are fetched here
                        # so each agent entry in the active/solved lists contains the
                        # full data.vulnerability.* payload alongside agent.ip/name.
                        "agents_with_status": {
                            "terms": {"field": "agent.name", "size": 100},
                            "aggs": {
                                "latest_status": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": [
                                            "agent.name",
                                            "agent.ip",
                                            "data.vulnerability.status",
                                            "data.vulnerability.title",
                                            "data.vulnerability.assigner",
                                            "data.vulnerability.classification",
                                            "data.vulnerability.cve",
                                            "data.vulnerability.severity",
                                            "data.vulnerability.published",
                                            "data.vulnerability.cvss.cvss3.base_score",
                                            "data.vulnerability.cvss.cvss3.vector.attack_vector",
                                            "data.vulnerability.cvss.cvss3.vector.confidentiality_impact",
                                            "data.vulnerability.score.base",
                                            "data.vulnerability.package.name",
                                            "data.vulnerability.rationale",
                                            "data.vulnerability.reference",
                                            "data.vulnerability.scanner.reference",
                                        ],
                                    }
                                }
                            },
                        },
                    },
                }
            },
        }

        # Three-state vulnerability status classification (case-insensitive):
        #   Active  → vulnerability still exists, requires immediate patching
        #   Pending → waiting for scan or update to confirm status; shown with asset details
        #   Solved  → package updated / vulnerability no longer detected
        _ACTIVE_STATUSES  = {'active', 'still applicable', 'unpatched'}
        _PENDING_STATUSES = {'pending', 'pending confirmation'}
        # Anything else (solved, fixed, patched, obsolete, …) is treated as Solved

        def _classify_agents(agg_bucket: dict):
            """
            Iterate the agents_with_status bucket and return (active_list, pending_list, solved_list).
            Classification is case-insensitive so it works regardless of Wazuh version.
            Each entry contains the full structured vulnerability data for that agent.
            """
            active_list, pending_list, solved_list = [], [], []
            for ab in agg_bucket.get('agents_with_status', {}).get('buckets', []):
                agent_name = ab.get('key', '')
                if not agent_name:
                    continue
                hits = ab.get('latest_status', {}).get('hits', {}).get('hits', [])
                src = hits[0].get('_source', {}) if hits else {}
                agent_src = src.get('agent', {})
                vuln_src = src.get('data', {}).get('vulnerability', {})
                cvss3_src = vuln_src.get('cvss', {}).get('cvss3', {})
                vector_src = cvss3_src.get('vector', {})

                raw_status = vuln_src.get('status', '') or ''
                normalised = raw_status.lower().strip()

                entry = {
                    'name':                   agent_src.get('name', '') or agent_name,
                    'ip':                     agent_src.get('ip', '') or '',
                    'location':               '',
                    # Structured vulnerability fields per agent
                    'vuln_title':             vuln_src.get('title', '') or '',
                    'vuln_assigner':          vuln_src.get('assigner', '') or '',
                    'vuln_classification':    vuln_src.get('classification', '') or '',
                    'vuln_cve':               vuln_src.get('cve', '') or '',
                    'vuln_severity':          vuln_src.get('severity', '') or '',
                    'vuln_status':            raw_status,
                    'vuln_published':         vuln_src.get('published', '') or '',
                    'cvss3_base_score':       cvss3_src.get('base_score', '') or '',
                    'cvss3_attack_vector':    vector_src.get('attack_vector', '') or '',
                    'cvss3_conf_impact':      vector_src.get('confidentiality_impact', '') or '',
                    'score_base':             vuln_src.get('score', {}).get('base', '') or '',
                    'package_name':           vuln_src.get('package', {}).get('name', '') or '',
                    'vuln_rationale':         vuln_src.get('rationale', '') or '',
                    'vuln_reference':         vuln_src.get('reference', '') or '',
                    'scanner_reference':      vuln_src.get('scanner', {}).get('reference', '') or '',
                }
                if normalised in _ACTIVE_STATUSES:
                    active_list.append(entry)
                elif normalised in _PENDING_STATUSES:
                    pending_list.append(entry)
                else:
                    # solved, fixed, patched, obsolete, or empty → treat as patched
                    solved_list.append(entry)
            return active_list, pending_list, solved_list

        resp = api.client.search(index="wazuh-alerts-*", body=agg_query, request_timeout=60)
        buckets = resp.get('aggregations', {}).get('unique_cves', {}).get('buckets', [])

        severity_map = {
            'critical': 'critical', 'high': 'high', 'medium': 'medium',
            'low': 'low', 'negligible': 'low', 'none': 'low',
        }

        for bucket in buckets:
            cve_id = bucket.get('key', '')
            if not cve_id:
                continue

            hits = bucket.get('top_hit', {}).get('hits', {}).get('hits', [])
            if not hits:
                continue
            src = hits[0].get('_source', {})
            vuln = src.get('data', {}).get('vulnerability', {})

            # ── Core vulnerability fields ───────────────────────────────────
            title_raw = vuln.get('title', '') or f"Vulnerability detected: {cve_id}"
            severity_raw = (vuln.get('severity') or 'Unknown').lower()
            severity = severity_map.get(severity_raw, 'unknown')

            cvss3   = vuln.get('cvss', {}).get('cvss3', {})
            cvss_score = float(
                vuln.get('score', {}).get('base', 0)
                or cvss3.get('base_score', 0)
                or vuln.get('cvss', {}).get('cvss2', {}).get('base_score', 0)
                or 0
            ) or 0.0
            try:
                cvss_score = float(cvss_score)
            except (TypeError, ValueError):
                cvss_score = 0.0

            cvss_vector    = cvss3.get('vector', {})
            attack_vector  = cvss_vector.get('attack_vector', '')
            conf_impact    = cvss_vector.get('confidentiality_impact', '')

            pkg       = vuln.get('package', {})
            pkg_name  = pkg.get('name', '')
            pkg_ver   = pkg.get('version', '')
            pkg_arch  = pkg.get('architecture', '')

            assigner       = vuln.get('assigner', '')
            classification = vuln.get('classification', '')
            rationale      = vuln.get('rationale', '')
            reference      = vuln.get('reference', '')
            scanner_ref    = vuln.get('scanner', {}).get('reference', '')
            published_raw  = vuln.get('published', '')

            description = rationale or vuln.get('description', '')
            if not description:
                # Build a neutral fallback — avoid Wazuh's "was solved/found" phrasing
                description = (
                    f"{cve_id} affects {pkg_name}" if pkg_name
                    else f"Vulnerability {cve_id} detected by Wazuh on endpoint agents."
                )
            ref_url = reference or f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}"
            published = _parse_date(published_raw or src.get('@timestamp', ''))

            # ── Active / Pending / Solved agent lists ────────────────────────
            # _classify_agents reads each agent's actual status value from the
            # latest matching document and classifies it case-insensitively,
            # so it works regardless of how Wazuh capitalises the status field.
            active_agents, pending_agents, solved_agents = _classify_agents(bucket)

            # Confirmed present (exposed) when Active OR Pending on ≥1 agent
            vuln_status = 'Active' if active_agents else ('Pending' if pending_agents else 'Solved')

            # ── Clean title ─────────────────────────────────────────────────
            clean_title_raw = (
                title_raw
                .replace(' was solved', '').replace(' was found', '')
                .replace(' still applies', '').strip().rstrip(',').strip()
            )
            title = cve_id
            if clean_title_raw and clean_title_raw != cve_id:
                title += f" – {clean_title_raw[:120]}"

            # ── Description: all structured fields in pipe-sep format ───────
            desc_parts = [description[:800] if description else '']
            if pkg_name:
                pkg_str = f"{pkg_name} {pkg_ver}".strip()
                if pkg_arch:
                    pkg_str += f" ({pkg_arch})"
                desc_parts.append(f"Affected package: {pkg_str}")
            if cvss_score:
                desc_parts.append(f"CVSS Score: {cvss_score}")
            if attack_vector:
                desc_parts.append(f"Attack Vector: {attack_vector}")
            if conf_impact:
                desc_parts.append(f"Confidentiality Impact: {conf_impact}")
            if assigner:
                desc_parts.append(f"Assigner: {assigner}")
            if classification:
                desc_parts.append(f"Classification: {classification}")
            if reference:
                desc_parts.append(f"Reference: {reference}")
            if scanner_ref:
                desc_parts.append(f"Scanner Reference: {scanner_ref}")
            desc_parts.append(f"Vuln Status: {vuln_status}")
            # Structured agent lists for correlation engine
            desc_parts.append(f"[WAZUH_ACTIVE_AGENTS:{json.dumps(active_agents)}]")
            desc_parts.append(f"[WAZUH_PENDING_AGENTS:{json.dumps(pending_agents)}]")
            desc_parts.append(f"[WAZUH_SOLVED_AGENTS:{json.dumps(solved_agents)}]")

            guid = _make_guid('wazuh_cti', cve_id)
            items.append({
                'guid': guid,
                'title': title[:500],
                'description': ' | '.join(desc_parts)[:4000],
                'url': ref_url,
                'source': 'wazuh_cti',
                'published_at': published,
                'severity': severity,
                'has_patch': (vuln_status == 'Solved') or (not active_agents and not pending_agents and _detect_patch(description)),
                'has_mitigation': _detect_mitigation(description),
                'cve_ids': [cve_id],
            })

        logger.info(
            f"Wazuh CTI: collected {len(items)} unique CVEs via aggregation "
            f"(limit={limit})"
        )

    except Exception as e:
        logger.error(
            f"Error fetching Wazuh CTI vulnerabilities from OpenSearch: {e}"
        )
    return items


def fetch_all_sources(active_sources=None) -> list:
    """Fetch from all enabled sources and return raw item dicts."""
    if active_sources is None:
        active_sources = list(FEED_SOURCES.keys())

    all_items = []
    for src_key in active_sources:
        src = FEED_SOURCES.get(src_key)
        if not src:
            continue
        try:
            if src['type'] == 'json_api' and src_key == 'cisa_kev':
                all_items.extend(fetch_cisa_kev())
            elif src['type'] == 'nvd_api':
                all_items.extend(fetch_nvd())
            elif src['type'] == 'rss':
                all_items.extend(fetch_rss(src_key))
            elif src['type'] == 'wazuh_cti':
                all_items.extend(fetch_wazuh_cti())
        except Exception as e:
            logger.error(f"Error fetching source {src_key}: {e}")
    return all_items


def store_new_items(app, raw_items: list) -> list:
    """
    Store new threat intel items in the database.
    Returns list of newly inserted ThreatIntelItem instances.
    """
    from models import ThreatIntelItem, db
    new_items = []
    with app.app_context():
        for raw in raw_items:
            guid = raw.get('guid')
            if not guid:
                continue
            if ThreatIntelItem.query.filter_by(guid=guid).first():
                continue
            item = ThreatIntelItem(
                guid=guid,
                title=raw.get('title', 'Unknown')[:500],
                description=raw.get('description', ''),
                url=raw.get('url', ''),
                source=raw.get('source', 'unknown'),
                published_at=raw.get('published_at'),
                severity=raw.get('severity', 'unknown'),
                has_patch=raw.get('has_patch', False),
                has_mitigation=raw.get('has_mitigation', False),
                cve_ids=json.dumps(raw.get('cve_ids', [])),
            )
            db.session.add(item)
            new_items.append(item)
        db.session.commit()
    logger.info(f"Stored {len(new_items)} new threat intel items")
    return new_items


def analyse_item_with_ai(item) -> dict:
    """
    Run AI analysis on a threat intel item.
    Returns dict with: summary, severity, has_patch, has_mitigation, relevance_score, recommended_action
    """
    try:
        from ai_insights import AIInsights
        ai = AIInsights()
        prompt = (
            f"You are a security analyst. Analyse the following cybersecurity threat:\n\n"
            f"Title: {item.title}\n"
            f"Source: {FEED_SOURCES.get(item.source, {}).get('name', item.source)}\n"
            f"Description: {item.description[:800]}\n\n"
            f"Please provide a JSON response with these exact fields:\n"
            f"  severity: one of critical/high/medium/low/informational\n"
            f"  relevance_score: integer 1-10 (10 = most relevant to a typical enterprise network)\n"
            f"  has_patch: true/false\n"
            f"  has_mitigation: true/false\n"
            f"  summary: 2-3 sentence plain-English summary of this threat\n"
            f"  recommended_action: 1-2 sentence action for the security team\n\n"
            f"Respond ONLY with valid JSON, no markdown."
        )
        result = ai.analyze_alerts(alerts_data=[], analysis_prompt=prompt)
        analysis_text = result.get('analysis', '')
        try:
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                return {
                    'severity': parsed.get('severity', item.severity),
                    'relevance_score': int(parsed.get('relevance_score', 5)),
                    'has_patch': bool(parsed.get('has_patch', item.has_patch)),
                    'has_mitigation': bool(parsed.get('has_mitigation', item.has_mitigation)),
                    'summary': parsed.get('summary', ''),
                    'recommended_action': parsed.get('recommended_action', ''),
                    'raw': analysis_text,
                }
        except (json.JSONDecodeError, ValueError):
            pass
        return {
            'severity': item.severity,
            'relevance_score': 5,
            'has_patch': item.has_patch,
            'has_mitigation': item.has_mitigation,
            'summary': analysis_text[:500],
            'recommended_action': '',
            'raw': analysis_text,
        }
    except Exception as e:
        logger.error(f"AI analysis failed for item {item.id}: {e}")
        return {
            'severity': item.severity,
            'relevance_score': 5,
            'has_patch': item.has_patch,
            'has_mitigation': item.has_mitigation,
            'summary': '',
            'recommended_action': '',
            'raw': str(e),
        }


def analyse_and_update_items(app, items, max_items=10):
    """Run AI analysis on unanalysed items and persist results."""
    from models import ThreatIntelItem, db
    updated = 0
    with app.app_context():
        unanalysed = (ThreatIntelItem.query
                      .filter_by(ai_analyzed=False)
                      .order_by(ThreatIntelItem.published_at.desc())
                      .limit(max_items).all())
        for item in unanalysed:
            result = analyse_item_with_ai(item)
            combined_text = f"{result.get('summary', '')} {result.get('recommended_action', '')}"
            item.ai_analysis = json.dumps(result)
            item.ai_analyzed = True
            item.severity = result.get('severity', item.severity)
            item.relevance_score = result.get('relevance_score', 5)
            item.has_patch = result.get('has_patch', item.has_patch)
            item.has_mitigation = result.get('has_mitigation', item.has_mitigation)
            db.session.commit()
            updated += 1
    logger.info(f"AI-analysed {updated} threat intel items")
    return updated


def send_threat_email(item, analysis: dict, recipient: str) -> bool:
    """Send an email alert for a threat intel item."""
    from config import Config
    if not Config.SMTP_USERNAME or not Config.SMTP_PASSWORD:
        logger.debug("SMTP not configured — skipping threat intel email")
        return False

    source_name = FEED_SOURCES.get(item.source, {}).get('name', item.source)
    sev_colour = {
        'critical': '#dc3545', 'high': '#fd7e14',
        'medium': '#ffc107', 'low': '#198754', 'unknown': '#6c757d',
    }.get(item.severity, '#6c757d')

    patch_badge = '✅ Patch Available' if item.has_patch else ''
    mitigation_badge = '🛡️ Mitigation Available' if item.has_mitigation else ''
    cve_list = ', '.join(item.get_cve_list()) or 'None listed'
    summary = analysis.get('summary', item.description[:300])
    action = analysis.get('recommended_action', 'Review and assess your exposure.')

    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px">
    <div style="max-width:700px;margin:auto;background:#161b22;border-radius:8px;padding:24px;border:1px solid #30363d">
      <h2 style="color:#f0f6fc;border-bottom:1px solid #30363d;padding-bottom:12px">
        ⚠️ Threat Intelligence Alert
      </h2>
      <div style="background:{sev_colour}22;border-left:4px solid {sev_colour};padding:12px;border-radius:4px;margin-bottom:16px">
        <strong style="color:{sev_colour};text-transform:uppercase">{item.severity}</strong>
        &nbsp;{patch_badge}&nbsp;{mitigation_badge}
      </div>
      <h3 style="color:#f0f6fc">{item.title}</h3>
      <p><strong>Source:</strong> {source_name}</p>
      <p><strong>CVEs:</strong> {cve_list}</p>
      <hr style="border-color:#30363d">
      <h4 style="color:#58a6ff">AI Summary</h4>
      <p>{summary}</p>
      <h4 style="color:#58a6ff">Recommended Action</h4>
      <p>{action}</p>
      <hr style="border-color:#30363d">
      <p style="font-size:12px;color:#8b949e">
        Published: {item.published_at.strftime('%Y-%m-%d %H:%M UTC') if item.published_at else 'Unknown'}
        &nbsp;|&nbsp;
        <a href="{item.url}" style="color:#58a6ff">Read Full Article</a>
      </p>
    </div>
    </body></html>
    """

    # Support comma-separated multiple recipients
    recipient_list = [r.strip() for r in recipient.split(',') if r.strip()]
    if not recipient_list:
        logger.warning("No valid recipients found in threat intel email_recipient field")
        return False

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"ByteIT SentinelX <{Config.SMTP_USERNAME}>"
        msg['To'] = ', '.join(recipient_list)
        msg['Subject'] = f"[Threat Intel] {item.severity.upper()}: {item.title[:80]}"
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            if Config.SMTP_USE_TLS:
                server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            server.sendmail(Config.SMTP_USERNAME, recipient_list, msg.as_string())
        logger.info(f"Threat intel email sent to {recipient_list} for: {item.title[:60]}")
        return True
    except Exception as e:
        logger.error(f"Failed to send threat intel email: {e}")
        return False


def send_pending_emails(app):
    """Send emails for items that qualify and haven't been emailed yet."""
    from models import ThreatIntelItem, ThreatIntelConfig, db
    from config import Config
    if not Config.SMTP_USERNAME or not Config.SMTP_PASSWORD:
        logger.warning("SMTP not configured — skipping threat intel emails")
        return 0
    with app.app_context():
        cfg = ThreatIntelConfig.get_instance()
        if not cfg.email_recipient or not cfg.enabled:
            return 0

        query = ThreatIntelItem.query.filter_by(email_sent=False, ai_analyzed=True)
        conditions = []
        if cfg.notify_on_patch:
            from sqlalchemy import or_
            conditions.append(ThreatIntelItem.has_patch == True)
            conditions.append(ThreatIntelItem.has_mitigation == True)
        if cfg.notify_on_critical:
            conditions.append(ThreatIntelItem.severity == 'critical')

        if conditions:
            from sqlalchemy import or_
            query = query.filter(or_(*conditions))
        query = query.filter(ThreatIntelItem.relevance_score >= cfg.min_relevance)

        sent = 0
        for item in query.limit(20).all():
            analysis = {}
            if item.ai_analysis:
                try:
                    analysis = json.loads(item.ai_analysis)
                except Exception:
                    pass
            if send_threat_email(item, analysis, cfg.email_recipient):
                item.email_sent = True
                db.session.commit()
                sent += 1
        logger.info(f"Sent {sent} threat intel emails")
        return sent


def send_threat_email_with_correlation(item, analysis: dict, correlation, recipient: str) -> bool:
    """Send an email alert enriched with infrastructure correlation data."""
    from config import Config
    if not Config.SMTP_USERNAME or not Config.SMTP_PASSWORD:
        logger.debug("SMTP not configured — skipping threat intel email")
        return False

    source_name = FEED_SOURCES.get(item.source, {}).get('name', item.source)
    sev_colour = {
        'critical': '#dc3545', 'high': '#fd7e14',
        'medium': '#ffc107', 'low': '#198754', 'unknown': '#6c757d',
    }.get(item.severity, '#6c757d')

    patch_badge = '✅ Patch Available' if item.has_patch else ''
    mitigation_badge = '🛡️ Mitigation Available' if item.has_mitigation else ''
    cve_list = ', '.join(item.get_cve_list()) or 'None listed'
    summary = analysis.get('summary', item.description[:300])
    generic_action = analysis.get('recommended_action', 'Review and assess your exposure.')

    confirmed_badge = ''
    correlation_block = ''
    env_action = generic_action

    if correlation:
        affected = correlation.get_affected_agents()
        env_action = correlation.env_recommended_action or generic_action
        env_summary = correlation.correlation_summary or ''
        env_score = correlation.env_relevance_score or 0
        is_confirmed = correlation.is_confirmed_present

        if is_confirmed:
            confirmed_badge = '🚨 <strong style="color:#dc3545">CONFIRMED IN YOUR ENVIRONMENT</strong>'
        elif affected:
            confirmed_badge = f'⚠️ <strong style="color:#fd7e14">{len(affected)} AGENT(S) POTENTIALLY AFFECTED</strong>'

        if affected:
            agent_rows = ''.join(
                f"<tr>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #30363d'>{a.get('name','')}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #30363d;color:#8b949e'>{a.get('ip','')}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #30363d;color:#8b949e'>{a.get('os','')}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #30363d;color:#f0a500'>{'; '.join(a.get('reasons',[]))}</td>"
                f"</tr>"
                for a in affected[:20]
            )
            correlation_block = f"""
      <hr style="border-color:#30363d">
      <h4 style="color:#f85149">Infrastructure Exposure Assessment</h4>
      {'<p style="color:#f85149;font-weight:bold">' + confirmed_badge + '</p>' if confirmed_badge else ''}
      <p style="color:#8b949e">Environment Relevance Score: <strong style="color:#f0f6fc">{env_score}/10</strong></p>
      <p>{env_summary}</p>
      <table style="width:100%;border-collapse:collapse;margin-top:8px">
        <thead><tr style="background:#21262d">
          <th style="padding:8px 10px;text-align:left;color:#f0f6fc">Agent</th>
          <th style="padding:8px 10px;text-align:left;color:#f0f6fc">IP</th>
          <th style="padding:8px 10px;text-align:left;color:#f0f6fc">OS</th>
          <th style="padding:8px 10px;text-align:left;color:#f0f6fc">Match Reason</th>
        </tr></thead>
        <tbody>{agent_rows}</tbody>
      </table>
"""

    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px">
    <div style="max-width:760px;margin:auto;background:#161b22;border-radius:8px;padding:24px;border:1px solid #30363d">
      <h2 style="color:#f0f6fc;border-bottom:1px solid #30363d;padding-bottom:12px">
        ⚠️ Threat Intelligence Alert — ByteIT SentinelX
      </h2>
      <div style="background:{sev_colour}22;border-left:4px solid {sev_colour};padding:12px;border-radius:4px;margin-bottom:16px">
        <strong style="color:{sev_colour};text-transform:uppercase">{item.severity}</strong>
        &nbsp;{patch_badge}&nbsp;{mitigation_badge}
        {'&nbsp;' + confirmed_badge if confirmed_badge else ''}
      </div>
      <h3 style="color:#f0f6fc">{item.title}</h3>
      <p><strong>Source:</strong> {source_name} &nbsp;|&nbsp; <strong>CVEs:</strong> {cve_list}</p>
      <hr style="border-color:#30363d">
      <h4 style="color:#58a6ff">AI Summary</h4>
      <p>{summary}</p>
      <h4 style="color:#58a6ff">Recommended Action</h4>
      <p>{env_action}</p>
      {correlation_block}
      <hr style="border-color:#30363d">
      <p style="font-size:12px;color:#8b949e">
        Published: {item.published_at.strftime('%Y-%m-%d %H:%M UTC') if item.published_at else 'Unknown'}
        &nbsp;|&nbsp;
        <a href="{item.url}" style="color:#58a6ff">Read Full Article</a>
      </p>
    </div>
    </body></html>
    """

    # Support comma-separated multiple recipients
    recipient_list = [r.strip() for r in recipient.split(',') if r.strip()]
    if not recipient_list:
        logger.warning("No valid recipients found in threat intel email_recipient field")
        return False

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"ByteIT SentinelX <{Config.SMTP_USERNAME}>"
        msg['To'] = ', '.join(recipient_list)
        prefix = "[CONFIRMED]" if (correlation and correlation.is_confirmed_present) else "[Threat Intel]"
        msg['Subject'] = f"{prefix} {item.severity.upper()}: {item.title[:80]}"
        msg.attach(MIMEText(body, 'html'))
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            if Config.SMTP_USE_TLS:
                server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            server.sendmail(Config.SMTP_USERNAME, recipient_list, msg.as_string())
        logger.info(f"Threat intel email sent to {recipient_list}: {item.title[:60]}")
        return True
    except Exception as e:
        logger.error(f"Failed to send threat intel email: {e}")
        return False


def send_pending_emails_with_correlation(app):
    """Send emails for qualifying items, enriching them with correlation data."""
    from models import ThreatIntelItem, ThreatIntelConfig, db
    from config import Config
    if not Config.SMTP_USERNAME or not Config.SMTP_PASSWORD:
        logger.warning("SMTP not configured — skipping threat intel emails")
        return 0
    with app.app_context():
        cfg = ThreatIntelConfig.get_instance()
        if not cfg.email_recipient or not cfg.enabled:
            return 0

        query = ThreatIntelItem.query.filter_by(email_sent=False, ai_analyzed=True)
        conditions = []
        if cfg.notify_on_patch:
            from sqlalchemy import or_
            conditions.append(ThreatIntelItem.has_patch == True)
            conditions.append(ThreatIntelItem.has_mitigation == True)
        if cfg.notify_on_critical:
            conditions.append(ThreatIntelItem.severity == 'critical')

        if conditions:
            from sqlalchemy import or_
            query = query.filter(or_(*conditions))
        query = query.filter(ThreatIntelItem.relevance_score >= cfg.min_relevance)

        sent = 0
        for item in query.limit(20).all():
            analysis = {}
            if item.ai_analysis:
                try:
                    analysis = json.loads(item.ai_analysis)
                except Exception:
                    pass
            correlation = item.correlation
            if send_threat_email_with_correlation(item, analysis, correlation, cfg.email_recipient):
                item.email_sent = True
                db.session.commit()
                sent += 1

        logger.info(f"Sent {sent} threat intel emails")
        return sent


def run_full_refresh(app):
    """Full pipeline: fetch → store → AI analyse → correlate → email."""
    logger.info("Starting threat intel full refresh")
    try:
        from models import ThreatIntelConfig
        with app.app_context():
            cfg = ThreatIntelConfig.get_instance()
            sources = cfg.get_sources()

        raw_items = fetch_all_sources(active_sources=sources)
        new_items = store_new_items(app, raw_items)
        analyse_and_update_items(app, new_items, max_items=15)

        try:
            from threat_intel_correlator import correlate_items
            correlate_items(app, max_items=20)
        except Exception as e:
            logger.error(f"Correlation step failed (non-fatal): {e}", exc_info=True)

        send_pending_emails_with_correlation(app)
        logger.info("Threat intel full refresh complete")
        return len(new_items)
    except Exception as e:
        logger.error(f"Threat intel refresh error: {e}", exc_info=True)
        return 0
