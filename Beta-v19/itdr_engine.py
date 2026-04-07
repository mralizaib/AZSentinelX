"""
ITDR / XDR Detection Engine
===========================
Continuously scans Wazuh/OpenSearch alert data for identity and endpoint threat
patterns, creates ITDRDetection records, correlates them into XDRIncidents, and
triggers the remediation policy engine.

Detection categories
--------------------
ITDR-001  Brute Force / Credential Attack
ITDR-002  Privilege Escalation
ITDR-003  Account Manipulation
ITDR-004  Lateral Movement (cross-agent same-source-IP)
ITDR-005  Malware / Ransomware
ITDR-006  Suspicious Process / Exploit
ITDR-007  File Integrity Violation (FIM spike)
ITDR-008  Network Anomaly / Scan
"""

import json
import uuid
import logging
from datetime import datetime, timedelta

from opensearch_api import OpenSearchAPI

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection rule definitions
# ---------------------------------------------------------------------------
DETECTION_RULES = [
    {
        'id': 'ITDR-001',
        'name': 'Brute Force / Credential Attack',
        'category': 'credential_attack',
        'severity': 'high',
        'icon': 'fas fa-user-lock',
        'color': '#f59e0b',
        'groups': [
            'authentication_failed', 'web-attack', 'brute_force',
            'win_failed_logon', 'authentication_failures', 'pam',
            'sshd', 'invalid_login', 'multiple_authentication_failure',
        ],
        'min_count': 5,
        'window_minutes': 10,
        'description': 'Multiple failed authentication attempts from a single source — credential stuffing or brute force.',
    },
    {
        'id': 'ITDR-002',
        'name': 'Privilege Escalation',
        'category': 'privilege_escalation',
        'severity': 'critical',
        'icon': 'fas fa-arrow-up',
        'color': '#ef4444',
        'groups': [
            'sudo', 'privilege-escalation', 'win_privilege_escalation',
            'local_privilege_escalation', 'suid_binary', 'setuid',
        ],
        'min_count': 1,
        'window_minutes': 60,
        'description': 'User or process has escalated privileges beyond normal boundaries.',
    },
    {
        'id': 'ITDR-003',
        'name': 'Account Manipulation',
        'category': 'account_manipulation',
        'severity': 'high',
        'icon': 'fas fa-user-edit',
        'color': '#f59e0b',
        'groups': [
            'account-changed', 'useradd', 'userdel', 'groupadd',
            'groupdel', 'win_account_change', 'adduser', 'deluser',
        ],
        'min_count': 1,
        'window_minutes': 60,
        'description': 'Accounts created, modified, or deleted — potential unauthorised identity change.',
    },
    {
        'id': 'ITDR-004',
        'name': 'Lateral Movement',
        'category': 'lateral_movement',
        'severity': 'critical',
        'icon': 'fas fa-network-wired',
        'color': '#ef4444',
        'groups': [
            'authentication_failed', 'smb', 'rdp', 'ssh', 'telnet',
            'authentication_success', 'successful_login',
        ],
        'min_count': 3,
        'window_minutes': 30,
        'multi_agent': True,
        'min_agents': 2,
        'description': 'Single source IP targeting multiple endpoints — potential lateral movement.',
    },
    {
        'id': 'ITDR-005',
        'name': 'Malware / Ransomware',
        'category': 'malware',
        'severity': 'critical',
        'icon': 'fas fa-bug',
        'color': '#ef4444',
        'groups': [
            'malware', 'ransomware', 'virus', 'trojans', 'spyware',
            'rootkit', 'backdoor', 'worm',
        ],
        'min_count': 1,
        'window_minutes': 60,
        'description': 'Malware or ransomware indicator detected on an endpoint.',
    },
    {
        'id': 'ITDR-006',
        'name': 'Suspicious Process / Exploit',
        'category': 'suspicious_execution',
        'severity': 'high',
        'icon': 'fas fa-terminal',
        'color': '#f59e0b',
        'groups': [
            'attack', 'process-monitoring', 'shellshock', 'web-attack',
            'exploit', 'execution', 'command-injection', 'code-injection',
        ],
        'min_count': 3,
        'window_minutes': 15,
        'description': 'Suspicious or exploit-like process activity detected.',
    },
    {
        'id': 'ITDR-007',
        'name': 'File Integrity Violation',
        'category': 'data_access',
        'severity': 'medium',
        'icon': 'fas fa-file-alt',
        'color': '#3b82f6',
        'groups': ['syscheck', 'fim', 'rootcheck'],
        'min_count': 15,
        'window_minutes': 60,
        'description': 'Unusual FIM alert volume — potential data access or tampering.',
    },
    {
        'id': 'ITDR-008',
        'name': 'Network Anomaly / Scan',
        'category': 'network_anomaly',
        'severity': 'medium',
        'icon': 'fas fa-satellite-dish',
        'color': '#3b82f6',
        'groups': [
            'network', 'port-scan', 'nmap', 'network-scan', 'firewall',
            'scan', 'ids', 'intrusion_detection',
        ],
        'min_count': 5,
        'window_minutes': 10,
        'description': 'Network scanning or anomalous connection patterns detected.',
    },
]

CATEGORY_LABELS = {
    'credential_attack':   'Credential Attack',
    'privilege_escalation':'Privilege Escalation',
    'account_manipulation':'Account Manipulation',
    'lateral_movement':    'Lateral Movement',
    'malware':             'Malware / Ransomware',
    'suspicious_execution':'Suspicious Execution',
    'data_access':         'File Integrity Violation',
    'network_anomaly':     'Network Anomaly',
}

# Deduplicate detections — same rule + source IP within this many minutes is the same event
DEDUP_WINDOW_MINUTES = 60


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_os_client():
    api = OpenSearchAPI()
    return api.client if (api and api.client) else None


def _iso(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%S')


def _scan_rule(client, rule: dict, since_dt: datetime) -> list:
    """
    Run one detection rule against OpenSearch.
    Returns a list of raw detection dicts (one per agent / source-IP combination).
    """
    groups = rule['groups']
    window_min = rule['window_minutes']
    rule_since = max(since_dt, datetime.utcnow() - timedelta(minutes=window_min))

    query = {
        'size': 0,
        'query': {
            'bool': {
                'filter': [
                    {'range': {'@timestamp': {'gte': _iso(rule_since)}}},
                ],
                'should': [{'term': {'rule.groups': g}} for g in groups],
                'minimum_should_match': 1,
            }
        },
        'aggs': {
            'by_agent': {
                'terms': {'field': 'agent.name', 'size': 100},
                'aggs': {
                    'by_src_ip': {
                        'terms': {'field': 'data.srcip', 'size': 30},
                        'aggs': {
                            'event_count': {'value_count': {'field': '@timestamp'}},
                            'first_seen':  {'min': {'field': '@timestamp'}},
                            'last_seen':   {'max': {'field': '@timestamp'}},
                            'top_desc':    {'terms': {'field': 'rule.description', 'size': 3}},
                            'top_rule_ids':{'terms': {'field': 'rule.id', 'size': 5}},
                        }
                    },
                    'no_ip_count': {
                        'filter': {'bool': {'must_not': {'exists': {'field': 'data.srcip'}}}},
                        'aggs': {
                            'event_count': {'value_count': {'field': '@timestamp'}},
                            'first_seen':  {'min': {'field': '@timestamp'}},
                            'last_seen':   {'max': {'field': '@timestamp'}},
                            'top_desc':    {'terms': {'field': 'rule.description', 'size': 3}},
                            'top_rule_ids':{'terms': {'field': 'rule.id', 'size': 5}},
                        }
                    },
                }
            }
        }
    }

    try:
        resp = client.search(index='wazuh-alerts-*', body=query, request_timeout=30)
    except Exception as exc:
        logger.warning(f"ITDR scan query failed for rule {rule['id']}: {exc}")
        return []

    detections = []
    for agent_bucket in resp.get('aggregations', {}).get('by_agent', {}).get('buckets', []):
        agent_name = agent_bucket.get('key', '')

        # Process per-source-IP sub-buckets
        for ip_bucket in agent_bucket.get('by_src_ip', {}).get('buckets', []):
            src_ip    = ip_bucket.get('key', '')
            count     = ip_bucket.get('event_count', {}).get('value', 0)
            first_raw = ip_bucket.get('first_seen',  {}).get('value_as_string', '')
            last_raw  = ip_bucket.get('last_seen',   {}).get('value_as_string', '')
            descs     = [b['key'] for b in ip_bucket.get('top_desc', {}).get('buckets', [])]
            rule_ids  = [b['key'] for b in ip_bucket.get('top_rule_ids', {}).get('buckets', [])]

            if count >= rule['min_count']:
                detections.append({
                    'agent_name': agent_name,
                    'src_ip':     src_ip,
                    'count':      count,
                    'first_seen': first_raw,
                    'last_seen':  last_raw,
                    'descriptions': descs,
                    'rule_ids':   rule_ids,
                })

        # Process events without a source IP (agent-internal events)
        no_ip = agent_bucket.get('no_ip_count', {})
        no_ip_count = no_ip.get('event_count', {}).get('value', 0)
        if no_ip_count >= rule['min_count']:
            descs    = [b['key'] for b in no_ip.get('top_desc', {}).get('buckets', [])]
            rule_ids = [b['key'] for b in no_ip.get('top_rule_ids', {}).get('buckets', [])]
            detections.append({
                'agent_name': agent_name,
                'src_ip':     '',
                'count':      no_ip_count,
                'first_seen': no_ip.get('first_seen', {}).get('value_as_string', ''),
                'last_seen':  no_ip.get('last_seen',  {}).get('value_as_string', ''),
                'descriptions': descs,
                'rule_ids':   rule_ids,
            })

    return detections


def _detect_lateral_movement(client, rule: dict, since_dt: datetime) -> list:
    """
    Special handler for lateral movement: detect a single source IP appearing
    across multiple agents in the scan window.
    """
    groups = rule['groups']
    window_min = rule['window_minutes']
    rule_since = max(since_dt, datetime.utcnow() - timedelta(minutes=window_min))

    query = {
        'size': 0,
        'query': {
            'bool': {
                'filter': [
                    {'range': {'@timestamp': {'gte': _iso(rule_since)}}},
                    {'exists': {'field': 'data.srcip'}},
                ],
                'should': [{'term': {'rule.groups': g}} for g in groups],
                'minimum_should_match': 1,
            }
        },
        'aggs': {
            'by_src_ip': {
                'terms': {'field': 'data.srcip', 'size': 100},
                'aggs': {
                    'event_count': {'value_count': {'field': '@timestamp'}},
                    'by_agent': {'terms': {'field': 'agent.name', 'size': 50}},
                    'first_seen': {'min': {'field': '@timestamp'}},
                    'last_seen':  {'max': {'field': '@timestamp'}},
                    'top_desc':   {'terms': {'field': 'rule.description', 'size': 3}},
                    'top_rule_ids': {'terms': {'field': 'rule.id', 'size': 5}},
                }
            }
        }
    }

    try:
        resp = client.search(index='wazuh-alerts-*', body=query, request_timeout=30)
    except Exception as exc:
        logger.warning(f"ITDR lateral movement query failed: {exc}")
        return []

    min_agents = rule.get('min_agents', 2)
    min_count  = rule.get('min_count', 3)
    detections = []

    for ip_bucket in resp.get('aggregations', {}).get('by_src_ip', {}).get('buckets', []):
        src_ip      = ip_bucket.get('key', '')
        total_count = ip_bucket.get('event_count', {}).get('value', 0)
        agents      = [b['key'] for b in ip_bucket.get('by_agent', {}).get('buckets', [])]
        first_raw   = ip_bucket.get('first_seen', {}).get('value_as_string', '')
        last_raw    = ip_bucket.get('last_seen',  {}).get('value_as_string', '')
        descs       = [b['key'] for b in ip_bucket.get('top_desc', {}).get('buckets', [])]
        rule_ids    = [b['key'] for b in ip_bucket.get('top_rule_ids', {}).get('buckets', [])]

        if total_count >= min_count and len(agents) >= min_agents:
            detections.append({
                'agent_name': ','.join(agents),
                'src_ip':     src_ip,
                'count':      total_count,
                'first_seen': first_raw,
                'last_seen':  last_raw,
                'descriptions': descs,
                'rule_ids':   rule_ids,
                'target_agents': agents,
            })

    return detections


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def run_itdr_scan(app):
    """
    Run the full ITDR scan.  Called by the scheduler every N minutes.
    Creates / updates ITDRDetection records, correlates into XDRIncidents,
    and triggers remediation policies for new detections.
    """
    with app.app_context():
        from models import db, ITDRDetection, XDRIncident

        client = _get_os_client()
        if not client:
            logger.warning('ITDR scan skipped — OpenSearch client not available')
            return

        logger.info('ITDR scan started')
        since_dt = datetime.utcnow() - timedelta(hours=2)
        new_detections = []

        for rule in DETECTION_RULES:
            try:
                if rule.get('multi_agent'):
                    raw_hits = _detect_lateral_movement(client, rule, since_dt)
                else:
                    raw_hits = _scan_rule(client, rule, since_dt)

                for hit in raw_hits:
                    det = _upsert_detection(app, rule, hit)
                    if det:
                        new_detections.append(det)
            except Exception as exc:
                logger.error(f"ITDR rule {rule['id']} scan error: {exc}", exc_info=True)

        if new_detections:
            _correlate_incidents(app, new_detections)
            _apply_remediation(app, new_detections)

        logger.info(f'ITDR scan complete — {len(new_detections)} new/updated detections')


def _upsert_detection(app, rule: dict, hit: dict):
    """
    Create or update an ITDRDetection record for this rule hit.
    Returns the detection if new/updated, None if it was a known duplicate.
    """
    from models import db, ITDRDetection

    rule_id    = rule['id']
    src_ip     = hit.get('src_ip', '') or ''
    agent_name = hit.get('agent_name', '') or ''
    count      = hit.get('count', 1)

    # Build dedup key: same rule + same source IP within the dedup window
    dedup_cutoff = datetime.utcnow() - timedelta(minutes=DEDUP_WINDOW_MINUTES)
    existing = (
        ITDRDetection.query
        .filter(
            ITDRDetection.rule_id == rule_id,
            ITDRDetection.source_ip == src_ip,
            ITDRDetection.last_seen >= dedup_cutoff,
        )
        .first()
    )

    if existing:
        # Update event count and timestamps
        existing.event_count = max(existing.event_count, count)
        try:
            existing.last_seen = datetime.utcnow()
        except Exception:
            pass
        db.session.commit()
        return None  # Not a new detection

    # Parse timestamps
    first_seen = last_seen = datetime.utcnow()
    try:
        if hit.get('first_seen'):
            first_seen = datetime.fromisoformat(hit['first_seen'].replace('Z', '+00:00').replace('+00:00', ''))
    except Exception:
        pass
    try:
        if hit.get('last_seen'):
            last_seen = datetime.fromisoformat(hit['last_seen'].replace('Z', '+00:00').replace('+00:00', ''))
    except Exception:
        pass

    target_agents = hit.get('target_agents') or ([agent_name] if agent_name else [])

    details = {
        'descriptions': hit.get('descriptions', []),
        'rule_ids':     hit.get('rule_ids', []),
        'event_count':  count,
    }

    det = ITDRDetection(
        detection_id=str(uuid.uuid4()),
        rule_id=rule_id,
        rule_name=rule['name'],
        category=rule['category'],
        severity=rule['severity'],
        source_ip=src_ip,
        target_agents=json.dumps(target_agents),
        event_count=count,
        first_seen=first_seen,
        last_seen=last_seen,
        detected_at=datetime.utcnow(),
        details=json.dumps(details),
        raw_rule_ids=json.dumps(hit.get('rule_ids', [])),
        alert_sent=False,
        remediated=False,
    )
    db.session.add(det)
    try:
        db.session.commit()
        logger.info(f"New ITDR detection: {rule_id} | {rule['name']} | {src_ip or agent_name}")
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to save ITDR detection: {exc}")
        return None

    return det


def _correlate_incidents(app, new_detections: list):
    """
    Group new detections into XDR incidents.
    Logic: detections sharing a source IP (or critical severity on same agent)
    within 30 minutes → same incident.
    """
    from models import db, XDRIncident, ITDRDetection

    window = timedelta(minutes=30)
    now = datetime.utcnow()

    for det in new_detections:
        if det.incident_id:
            continue

        # Look for an open incident with the same source IP in the correlation window
        existing_incident = None
        if det.source_ip:
            existing_incident = (
                XDRIncident.query
                .filter(
                    XDRIncident.status.in_(['open', 'investigating']),
                    XDRIncident.source_ips.contains(det.source_ip),
                    XDRIncident.updated_at >= now - window,
                )
                .first()
            )

        if existing_incident:
            # Attach to existing incident
            det.incident_id = existing_incident.id
            _update_incident(existing_incident, det)
        else:
            # Check if severity warrants its own incident
            if det.severity in ('critical', 'high'):
                incident = _create_incident(det)
                det.incident_id = incident.id

        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.error(f"Incident correlation commit failed: {exc}")


def _create_incident(det) -> 'XDRIncident':
    from models import db, XDRIncident

    # Generate sequential incident number
    count = XDRIncident.query.count() + 1
    inc_num = f'INC-{count:04d}'

    agents = det.get_target_agents()
    src_ips = [det.source_ip] if det.source_ip else []

    inc = XDRIncident(
        incident_number=inc_num,
        title=f'{det.rule_name} detected' + (f' from {det.source_ip}' if det.source_ip else ''),
        status='open',
        severity=det.severity,
        categories=json.dumps([det.category]),
        affected_agents=json.dumps(agents),
        source_ips=json.dumps(src_ips),
        detection_count=1,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        recommended_actions=json.dumps(_default_actions(det)),
    )
    db.session.add(inc)
    db.session.flush()
    return inc


def _update_incident(incident, det):
    cats    = incident.get_categories()
    agents  = incident.get_affected_agents()
    src_ips = incident.get_source_ips()

    if det.category not in cats:
        cats.append(det.category)
    for a in det.get_target_agents():
        if a not in agents:
            agents.append(a)
    if det.source_ip and det.source_ip not in src_ips:
        src_ips.append(det.source_ip)

    incident.categories       = json.dumps(cats)
    incident.affected_agents  = json.dumps(agents)
    incident.source_ips       = json.dumps(src_ips)
    incident.detection_count  = (incident.detection_count or 0) + 1
    incident.updated_at       = datetime.utcnow()

    # Escalate severity if needed
    sev_rank = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    if sev_rank.get(det.severity, 0) > sev_rank.get(incident.severity, 0):
        incident.severity = det.severity


def _default_actions(det) -> list:
    actions = {
        'credential_attack':   ['Block source IP at firewall', 'Enforce MFA on affected accounts', 'Review authentication logs'],
        'privilege_escalation':['Audit sudo/admin access immediately', 'Isolate affected endpoint', 'Review privilege change history'],
        'account_manipulation':['Verify account changes with HR/IT', 'Freeze newly created accounts', 'Review AD/LDAP logs'],
        'lateral_movement':    ['Block source IP across all segments', 'Isolate affected endpoints', 'Review east-west traffic'],
        'malware':             ['Quarantine endpoint immediately', 'Run full AV scan', 'Collect forensic image'],
        'suspicious_execution':['Kill suspicious process', 'Review process tree', 'Check for persistence mechanisms'],
        'data_access':         ['Review accessed files', 'Check for data exfiltration indicators', 'Audit FIM baselines'],
        'network_anomaly':     ['Block scanning source at perimeter', 'Review exposed services', 'Enable IDS signatures'],
    }
    return actions.get(det.category, ['Investigate and contain'])


def _apply_remediation(app, new_detections: list):
    """Apply matching remediation policies to new detections."""
    try:
        from remediation_engine import apply_policies
        apply_policies(app, new_detections)
    except Exception as exc:
        logger.error(f'Remediation engine error: {exc}', exc_info=True)


# ---------------------------------------------------------------------------
# Public helpers for the route layer
# ---------------------------------------------------------------------------

def get_detection_rule_meta() -> list:
    """Return lightweight rule metadata for the UI (no query logic)."""
    return [
        {
            'id': r['id'],
            'name': r['name'],
            'category': r['category'],
            'severity': r['severity'],
            'icon': r.get('icon', 'fas fa-shield-alt'),
            'color': r.get('color', '#6b7280'),
            'description': r['description'],
        }
        for r in DETECTION_RULES
    ]
