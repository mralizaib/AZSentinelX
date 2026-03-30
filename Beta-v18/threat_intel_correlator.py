"""
Threat Intelligence Correlation Engine for ByteIT SentinelX

Matches incoming threat intel items against the internal Wazuh agent inventory,
alert logs, and vulnerability scan data to determine which internal assets are
at risk and generate environment-specific AI recommendations.
"""
import logging
import json
import re
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

WINDOWS_KEYWORDS = [
    'windows', 'microsoft', 'outlook', 'office 365', 'ms office', 'active directory',
    'ntfs', 'ntlm', 'kerberos', 'remote desktop', 'rdp', 'smb', 'iis', 'defender',
    'exchange server', 'sharepoint', '.net framework', 'powershell', 'win32',
]
LINUX_KEYWORDS = [
    'linux', 'ubuntu', 'debian', 'centos', 'rhel', 'red hat',
    'openssl', 'bash', 'sudo', 'kernel', 'glibc', 'systemd',
]
NETWORK_KEYWORDS = [
    'sonicwall', 'cisco', 'fortinet', 'paloalto', 'palo alto', 'fortigate',
    'juniper', 'firewall', 'vpn', 'router', 'switch', 'asa', 'meraki',
]

# Web application / CMS keywords — these run ON Linux but only affect specific web servers,
# not every Linux host. Threats matching these are handled separately.
WEBAPP_KEYWORDS = [
    'wordpress', 'wp-', 'drupal', 'joomla', 'magento', 'prestashop',
    'typo3', 'moodle', 'mediawiki', 'confluence', 'jira', 'gitlab',
    'php', 'laravel', 'symfony', 'codeigniter', 'yii', 'zend',
    'apache tomcat', 'tomcat', 'jenkins', 'grafana', 'kibana',
]
# Host name fragments that suggest a web-server role
WEB_SERVER_NAME_HINTS = [
    'web', 'www', 'http', 'apache', 'nginx', 'lamp', 'srv-web',
    'server-web', 'front', 'portal', 'cms', 'app',
]


def get_agent_inventory(app) -> list:
    """Fetch all active agents from Wazuh with their OS and metadata."""
    try:
        from wazuh_api import WazuhAPI
        api = WazuhAPI()
        resp = api.get_agents(filters={'limit': 500})
        affected = resp.get('data', {}).get('affected_items', [])
        inventory = []
        for agent in affected:
            os_info = agent.get('os', {})
            labels = agent.get('labels', {})
            agent_name = agent.get('name', '')
            # Prefer explicit location label, fall back to department label,
            # then derive from agent name prefix (e.g. "CMS-81-12" → "CMS")
            if isinstance(labels, dict):
                location = (
                    labels.get('location', {}).get('set', '')
                    or labels.get('agent', {}).get('set', '')
                )
            else:
                location = ''
            if not location and agent_name:
                location = agent_name.split('-')[0]
            inventory.append({
                'id': agent.get('id', ''),
                'name': agent_name,
                'ip': agent.get('ip', ''),
                'status': agent.get('status', ''),
                'os_name': os_info.get('name', ''),
                'os_platform': os_info.get('platform', '').lower(),
                'os_version': os_info.get('version', ''),
                'os_major': str(os_info.get('major', '')),
                'os_build': os_info.get('build', ''),
                'location': location,
            })
        logger.info(f"Correlation engine: fetched {len(inventory)} agents from Wazuh")
        return inventory
    except Exception as e:
        logger.error(f"Error fetching agent inventory: {e}")
        return []


def search_cves_in_alerts(cve_ids: list, days_back: int = 30) -> list:
    """Search OpenSearch alert logs for any mention of given CVE IDs."""
    if not cve_ids:
        return []
    try:
        from opensearch_api import OpenSearchAPI
        api = OpenSearchAPI()
        if not api.client:
            return []

        end = datetime.utcnow()
        start = end - timedelta(days=days_back)

        should_clauses = [
            {"multi_match": {"query": cve, "fields": ["*"], "type": "phrase"}}
            for cve in cve_ids
        ]
        query = {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "filter": [{"range": {"@timestamp": {
                    "gte": start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                    "lte": end.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                }}}],
            }
        }
        resp = api.client.search(
            index=api.index_pattern,
            body={
                "query": query,
                "size": 20,
                "_source": ["agent.name", "agent.id", "rule.description", "rule.id", "@timestamp"],
            },
        )
        hits = resp.get('hits', {}).get('hits', [])
        matches = []
        seen = set()
        for hit in hits:
            src = hit.get('_source', {})
            agent_name = src.get('agent', {}).get('name', '')
            agent_id = src.get('agent', {}).get('id', '')
            if agent_name and agent_name not in seen:
                seen.add(agent_name)
                matches.append({
                    'agent_name': agent_name,
                    'agent_id': agent_id,
                    'rule_desc': src.get('rule', {}).get('description', ''),
                    'timestamp': src.get('@timestamp', ''),
                })
        logger.info(f"CVE alert search: found {len(matches)} matching agents for {cve_ids}")
        return matches
    except Exception as e:
        logger.error(f"Error searching CVEs in alert logs: {e}")
        return []


def match_agents_to_threat(item, agents: list) -> list:
    """
    Determine which agents from the inventory are potentially affected by this threat.
    Returns a list of affected agent dicts, each with a 'reasons' list.

    Web application threats (WordPress, PHP, Drupal, etc.) are treated separately:
    they do NOT flag every Linux host — only agents whose hostname suggests a web-server
    role, or agents found via CVE alert-log search (added by the caller).
    """
    affected = []
    title_lower = item.title.lower()
    desc_lower = (item.description or '').lower()
    combined = f"{title_lower} {desc_lower}"

    # Determine the primary threat category
    matched_webapp = [kw for kw in WEBAPP_KEYWORDS if kw in combined]
    is_webapp = len(matched_webapp) > 0

    is_windows = any(kw in combined for kw in WINDOWS_KEYWORDS)
    # Only treat as a generic Linux OS threat if no web-app keyword was matched
    # (web apps run on Linux but aren't OS-level vulnerabilities)
    is_linux = (not is_webapp) and any(kw in combined for kw in LINUX_KEYWORDS)
    is_network = any(kw in combined for kw in NETWORK_KEYWORDS)

    win_versions_mentioned = re.findall(
        r'windows(?:\s+server)?\s+(\d+(?:\.\d+)?)', combined, re.IGNORECASE
    )
    win_years_mentioned = re.findall(r'windows\s+server\s+(20\d\d)', combined, re.IGNORECASE)

    for agent in agents:
        reasons = []
        os_platform = agent.get('os_platform', '')
        os_name_full = f"{agent.get('os_name', '')} {agent.get('os_version', '')}".lower()
        agent_name_lower = agent.get('name', '').lower()

        # --- Windows OS match ---
        if is_windows and 'windows' in os_platform:
            if win_versions_mentioned:
                for ver in win_versions_mentioned:
                    if ver in os_name_full:
                        reasons.append(f"Running Windows {ver} — explicitly mentioned in threat")
                        break
                else:
                    reasons.append("Running Windows OS — threat targets Microsoft/Windows platform")
            elif win_years_mentioned:
                for yr in win_years_mentioned:
                    if yr in os_name_full:
                        reasons.append(f"Running Windows Server {yr} — explicitly mentioned in threat")
                        break
                else:
                    reasons.append("Running Windows Server — threat targets Windows Server platform")
            else:
                reasons.append("Running Windows OS — threat targets Microsoft/Windows platform")

        # --- Generic Linux OS match (only for true OS-level threats) ---
        if is_linux and 'linux' in os_platform:
            reasons.append("Running Linux OS — threat targets Linux platform")

        # --- Web application match (role-based, not OS-based) ---
        if is_webapp and 'linux' in os_platform:
            app_names = ", ".join(matched_webapp[:3])
            # Only flag if agent name hints it is a web server
            is_web_host = any(hint in agent_name_lower for hint in WEB_SERVER_NAME_HINTS)
            if is_web_host:
                reasons.append(
                    f"Host name suggests web-server role — threat targets web application "
                    f"({app_names})"
                )

        # --- Network device match ---
        if is_network:
            for kw in NETWORK_KEYWORDS:
                if kw in agent_name_lower:
                    reasons.append(
                        f"Agent '{agent.get('name')}' matches network device keyword '{kw}'"
                    )
                    break

        if reasons:
            affected.append({
                'id': agent.get('id'),
                'name': agent.get('name'),
                'ip': agent.get('ip'),
                'os': f"{agent.get('os_name', '')} {agent.get('os_version', '')}".strip(),
                'location': agent.get('location', ''),
                'reasons': reasons,
                'match_source': 'inventory',
            })

    return affected


def get_env_ai_analysis(item, affected_agents: list, alert_matches: list) -> dict:
    """
    Ask AI to assess this threat specifically against the detected environment context.
    Returns env_relevance_score, env_summary, env_recommended_action, is_confirmed_present.
    """
    try:
        from ai_insights import AIInsights
        from threat_intel_service import FEED_SOURCES

        cve_str = ", ".join(item.get_cve_list()) or "None listed"
        source_name = FEED_SOURCES.get(item.source, {}).get('name', item.source)

        if affected_agents:
            agent_lines = "\n".join(
                f"  - {a['name']} ({a['ip'] or 'IP unknown'}) — OS: {a['os'] or 'unknown'}"
                f" — Location: {a['location'] or 'unknown'}"
                f" — Match reason: {'; '.join(a['reasons'])}"
                for a in affected_agents[:15]
            )
            agent_block = f"Potentially affected agents ({len(affected_agents)} found):\n{agent_lines}"
        else:
            agent_block = "No direct OS/software match found in the agent inventory."

        alert_block = ""
        if alert_matches:
            names = ", ".join(set(m['agent_name'] for m in alert_matches[:5]))
            alert_block = (
                f"\nIMPORTANT: CVE ID(s) were found in recent alert logs from {len(alert_matches)} agent(s): {names}. "
                f"This suggests the threat may already be active or was previously seen in this environment."
            )

        prompt = (
            f"You are a senior security analyst reviewing a threat intelligence item "
            f"against a specific organisation's internal infrastructure.\n\n"
            f"THREAT DETAILS:\n"
            f"  Title: {item.title}\n"
            f"  Source: {source_name}\n"
            f"  Severity: {item.severity}\n"
            f"  CVEs: {cve_str}\n"
            f"  Description: {(item.description or '')[:700]}\n\n"
            f"INTERNAL ENVIRONMENT CONTEXT:\n"
            f"{agent_block}{alert_block}\n\n"
            f"Based strictly on this environment context, respond ONLY with valid JSON (no markdown):\n"
            f"{{\n"
            f"  \"env_relevance_score\": <integer 1-10, where 10 means this threat directly affects this org>,\n"
            f"  \"env_summary\": \"<2-3 sentences: does this threat affect this specific environment and why?>\",\n"
            f"  \"env_recommended_action\": \"<specific, actionable remediation steps, referencing affected agent names where possible>\",\n"
            f"  \"is_confirmed_present\": <true if CVE/indicator was found in alert logs, otherwise false>\n"
            f"}}"
        )

        ai = AIInsights()
        result = ai.analyze_alerts(alerts_data=[], analysis_prompt=prompt)
        text = result.get('analysis', '')
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            return {
                'env_relevance_score': min(10, max(1, int(parsed.get('env_relevance_score', 5)))),
                'env_summary': str(parsed.get('env_summary', '')),
                'env_recommended_action': str(parsed.get('env_recommended_action', '')),
                'is_confirmed_present': bool(parsed.get('is_confirmed_present', False)),
            }
    except Exception as e:
        logger.error(f"AI environment analysis failed: {e}")

    fallback_score = min(10, max(1, len(affected_agents) * 2)) if affected_agents else 1
    return {
        'env_relevance_score': fallback_score,
        'env_summary': (
            f"Found {len(affected_agents)} potentially affected agent(s) in inventory."
            if affected_agents else "No matching agents found in inventory."
        ),
        'env_recommended_action': (
            "Review the affected agents listed above and apply available patches or mitigations immediately."
            if affected_agents else "No immediate action required — monitor for new intelligence."
        ),
        'is_confirmed_present': len(alert_matches) > 0,
    }


def _parse_wazuh_agent_list(description: str, marker: str) -> list:
    """
    Extract a structured agent list embedded by fetch_wazuh_cti.
    marker is one of: WAZUH_ACTIVE_AGENTS, WAZUH_SOLVED_AGENTS, WAZUH_DETECTED_AGENTS.
    Returns a list (of dicts or strings) or [] if absent.
    """
    import re as _re, json as _json
    pattern = rf'\[{_re.escape(marker)}:(\[[\s\S]*?\])\]'
    match = _re.search(pattern, description or '')
    if match:
        try:
            return _json.loads(match.group(1))
        except Exception:
            pass
    return []


def _parse_wazuh_detected_agents(description: str) -> list:
    """
    Back-compat: return name strings from any embedded agent marker.
    Prefers the new WAZUH_ACTIVE_AGENTS marker, falls back to legacy
    WAZUH_DETECTED_AGENTS (which stored plain name strings).
    """
    active = _parse_wazuh_agent_list(description, 'WAZUH_ACTIVE_AGENTS')
    if active:
        return [a['name'] if isinstance(a, dict) else a for a in active]
    legacy = _parse_wazuh_agent_list(description, 'WAZUH_DETECTED_AGENTS')
    return [a if isinstance(a, str) else a.get('name', '') for a in legacy]


def correlate_threat_item(item, agents: list) -> dict:
    """
    Run the full correlation pipeline for a single threat intel item.

    For items sourced from the Wazuh Vulnerability Detector (source='wazuh_cti'),
    the CVE was *directly detected* on specific agents by Wazuh itself.  Those
    items are treated as confirmed-present from the start: the affected-agent list
    is built from the embedded Wazuh detection data rather than from generic keyword
    matching, and is_confirmed_present is forced True.  This eliminates false
    positives in the Exposed Inventory for external-feed items while ensuring
    every genuine Wazuh detection is surfaced accurately.
    """
    cve_list = item.get_cve_list()
    is_wazuh_cti = getattr(item, 'source', '') == 'wazuh_cti'

    if is_wazuh_cti:
        # --- Wazuh Vulnerability Detector path ---
        # fetch_wazuh_cti embeds two separate structured agent lists:
        #   [WAZUH_ACTIVE_AGENTS:...]  = agents where the CVE is still unpatched
        #   [WAZUH_SOLVED_AGENTS:...]  = agents where the patch was already applied
        # Each entry is {name, ip, location}.
        desc = getattr(item, 'description', '') or ''
        raw_active  = _parse_wazuh_agent_list(desc, 'WAZUH_ACTIVE_AGENTS')
        raw_solved  = _parse_wazuh_agent_list(desc, 'WAZUH_SOLVED_AGENTS')

        # Fall back to legacy marker if new ones absent (older stored records)
        if not raw_active and not raw_solved:
            legacy = _parse_wazuh_agent_list(desc, 'WAZUH_DETECTED_AGENTS')
            if legacy:
                raw_active = [
                    {'name': n, 'ip': '', 'location': ''} if isinstance(n, str) else n
                    for n in legacy
                ]

        inv_by_name = {a['name'].lower(): a for a in agents}
        cve_label = cve_list[0] if cve_list else 'CVE'

        def _build_agent_entry(raw, vuln_status_flag):
            """Convert a raw agent record to the correlation agent dict."""
            name = raw.get('name', '') if isinstance(raw, dict) else raw
            inv = inv_by_name.get(name.lower())
            location = (
                (raw.get('location') if isinstance(raw, dict) else '') or
                (inv.get('location', '') if inv else '') or
                name.split('-')[0]
            )
            ip = (
                (raw.get('ip') if isinstance(raw, dict) else '') or
                (inv.get('ip', '') if inv else '')
            )
            return {
                'id':    inv['id'] if inv else '',
                'name':  inv['name'] if inv else name,
                'ip':    ip,
                'os':    f"{inv.get('os_name','')} {inv.get('os_version','')}".strip() if inv else '',
                'location': location,
                'vuln_status': vuln_status_flag,   # 'Active' or 'Solved'
                'reasons': [
                    f"Wazuh Vulnerability Detector — {cve_label} is "
                    f"{'UNPATCHED' if vuln_status_flag == 'Active' else 'PATCHED'} on this agent"
                ],
                'match_source': 'wazuh_vuln_detector',
            }

        seen = set()
        affected_agents = []
        for raw in raw_active:
            n = (raw.get('name') if isinstance(raw, dict) else raw) or ''
            if n and n not in seen:
                seen.add(n)
                affected_agents.append(_build_agent_entry(raw, 'Active'))
        for raw in raw_solved:
            n = (raw.get('name') if isinstance(raw, dict) else raw) or ''
            if n and n not in seen:
                seen.add(n)
                affected_agents.append(_build_agent_entry(raw, 'Solved'))

        # is_confirmed_present = True only when at least one agent is still Active
        is_confirmed = any(a['vuln_status'] == 'Active' for a in affected_agents)
        active_count = sum(1 for a in affected_agents if a['vuln_status'] == 'Active')
        solved_count = sum(1 for a in affected_agents if a['vuln_status'] == 'Solved')

        summary = (
            f"Wazuh Vulnerability Detector: {cve_label} is UNPATCHED on "
            f"{active_count} agent(s) and PATCHED on {solved_count} agent(s)."
            if active_count else
            f"Wazuh Vulnerability Detector: {cve_label} has been PATCHED on all "
            f"{solved_count} detected agent(s)."
        )
        action = (
            f"Apply the available patch to all {active_count} agent(s) listed as UNPATCHED immediately."
            if active_count else
            "All detected agents have the patch applied. No immediate action required."
        )

        return {
            'affected_agents': affected_agents,
            'affected_count': len(affected_agents),
            'alert_matches': [],
            'env_relevance_score': min(10, max(1, active_count)),
            'env_summary': summary,
            'env_recommended_action': action,
            'is_confirmed_present': is_confirmed,
        }

    # --- External-feed path (CISA KEV, NVD, RSS news, etc.) ---
    # Keyword matching provides candidate agents; alert-log search provides
    # confirmed ones.  is_confirmed_present is only True when the exact CVE ID
    # was found in Wazuh alert logs — not merely because keywords matched.
    affected_agents = match_agents_to_threat(item, agents)

    alert_matches = search_cves_in_alerts(cve_list) if cve_list else []

    existing_ids = {a['id'] for a in affected_agents}
    for match in alert_matches:
        if match['agent_id'] not in existing_ids:
            inventory_agent = next((a for a in agents if a['id'] == match['agent_id']), None)
            if inventory_agent:
                affected_agents.append({
                    'id': inventory_agent['id'],
                    'name': inventory_agent['name'],
                    'ip': inventory_agent['ip'],
                    'os': f"{inventory_agent.get('os_name', '')} {inventory_agent.get('os_version', '')}".strip(),
                    'location': inventory_agent.get('location', ''),
                    'reasons': [f"CVE ID found in recent alert logs (rule: {match['rule_desc']})"],
                    'match_source': 'alert_logs',
                })
                existing_ids.add(match['agent_id'])
            else:
                affected_agents.append({
                    'id': match['agent_id'],
                    'name': match['agent_name'],
                    'ip': '',
                    'os': '',
                    'location': '',
                    'reasons': [f"CVE ID found in recent alert logs (rule: {match['rule_desc']})"],
                    'match_source': 'alert_logs',
                })
                existing_ids.add(match['agent_id'])

    # For external feeds, only mark confirmed if CVE was actually found in logs
    is_confirmed_present = len(alert_matches) > 0

    ai_result = get_env_ai_analysis(item, affected_agents, alert_matches)
    # Respect AI confirmation only as a supplement, not to override log evidence
    if ai_result.get('is_confirmed_present') and alert_matches:
        is_confirmed_present = True

    return {
        'affected_agents': affected_agents,
        'affected_count': len(affected_agents),
        'alert_matches': alert_matches,
        'env_relevance_score': ai_result['env_relevance_score'],
        'env_summary': ai_result['env_summary'],
        'env_recommended_action': ai_result['env_recommended_action'],
        'is_confirmed_present': is_confirmed_present,
    }


def correlate_items(app, items=None, max_items=20) -> int:
    """
    Run correlation for recent unprocessed threat intel items.
    Fetches the agent inventory once, then correlates each item.
    """
    from models import ThreatIntelItem, ThreatIntelCorrelation, db

    correlated = 0
    try:
        with app.app_context():
            agents = get_agent_inventory(app)
            if not agents:
                logger.warning("Correlation skipped — no agents returned from Wazuh")
                return 0

            if items is None:
                correlated_ids = db.session.query(ThreatIntelCorrelation.threat_intel_item_id).all()
                correlated_ids = {r[0] for r in correlated_ids}
                items = (
                    ThreatIntelItem.query
                    .filter_by(ai_analyzed=True)
                    .filter(~ThreatIntelItem.id.in_(correlated_ids) if correlated_ids else True)
                    .order_by(ThreatIntelItem.published_at.desc())
                    .limit(max_items)
                    .all()
                )

            logger.info(f"Correlating {len(items)} threat intel items against {len(agents)} agents")

            for item in items:
                try:
                    result = correlate_threat_item(item, agents)

                    existing = ThreatIntelCorrelation.query.filter_by(
                        threat_intel_item_id=item.id
                    ).first()
                    if existing:
                        corr = existing
                    else:
                        corr = ThreatIntelCorrelation(threat_intel_item_id=item.id)
                        db.session.add(corr)

                    corr.affected_agents = json.dumps(result['affected_agents'])
                    corr.affected_count = result['affected_count']
                    corr.env_relevance_score = result['env_relevance_score']
                    corr.env_recommended_action = result['env_recommended_action']
                    corr.correlation_summary = result['env_summary']
                    corr.is_confirmed_present = result['is_confirmed_present']
                    corr.correlated_at = datetime.utcnow()
                    db.session.commit()

                    logger.info(
                        f"Correlated '{item.title[:50]}': "
                        f"{result['affected_count']} agents, "
                        f"env_score={result['env_relevance_score']}, "
                        f"confirmed={result['is_confirmed_present']}"
                    )
                    correlated += 1
                except Exception as e:
                    logger.error(f"Error correlating item {item.id}: {e}", exc_info=True)
                    db.session.rollback()
                    continue

    except Exception as e:
        logger.error(f"Correlation engine error: {e}", exc_info=True)

    logger.info(f"Correlation complete: {correlated} items processed")
    return correlated


def correlate_single_item(app, item_id: int) -> dict:
    """Correlate a single item by ID. Used by manual trigger from the UI."""
    from models import ThreatIntelItem, ThreatIntelCorrelation, db

    with app.app_context():
        item = ThreatIntelItem.query.get(item_id)
        if not item:
            return {'error': 'Item not found'}

        agents = get_agent_inventory(app)
        if not agents:
            return {'error': 'No agents available from Wazuh'}

        result = correlate_threat_item(item, agents)

        existing = ThreatIntelCorrelation.query.filter_by(threat_intel_item_id=item.id).first()
        if existing:
            corr = existing
        else:
            corr = ThreatIntelCorrelation(threat_intel_item_id=item.id)
            db.session.add(corr)

        corr.affected_agents = json.dumps(result['affected_agents'])
        corr.affected_count = result['affected_count']
        corr.env_relevance_score = result['env_relevance_score']
        corr.env_recommended_action = result['env_recommended_action']
        corr.correlation_summary = result['env_summary']
        corr.is_confirmed_present = result['is_confirmed_present']
        corr.correlated_at = datetime.utcnow()
        db.session.commit()

        return {
            'affected_count': result['affected_count'],
            'env_relevance_score': result['env_relevance_score'],
            'env_summary': result['env_summary'],
            'env_recommended_action': result['env_recommended_action'],
            'is_confirmed_present': result['is_confirmed_present'],
            'affected_agents': result['affected_agents'],
        }
