"""
Log Filter / Noise Suppression Engine
======================================
Centralises all noise suppression logic for ByteIT SentinelX.

Responsibilities
----------------
1.  Load active NoiseFilter records from the database and expose them as
    OpenSearch query clauses that can be inserted into any search as
    ``must_not`` filters.
2.  Evaluate individual alert dicts (from OpenSearch ``_source``) to decide
    whether they should be stored or processed.
3.  Seed the database with evidence-based default filters on first startup.
4.  Provide a live signal-to-noise analysis API for the management UI.

Default filters seeded (based on SOC log analysis, April 2026)
---------------------------------------------------------------
Rule 4804  – SonicWall IKEv2 Unable to find IKE SA          (~295 k/day, lvl 3)
Rule 4803  – SonicWall error message                          (~53 k/day, lvl 4)
Rule 61102 – Windows System DCOM error event                  (~47 k/day, lvl 5)
Rule 61107 – TacticalRMM Agent Service terminated             (~18 k/day, lvl 5)
Rule 60608 – Report signature summary event                   (~14 k/day, lvl 4)
Rule 60642 – Software protection scheduled                    (~8.8k/day, lvl 3)
Rule 750   – Registry Value Integrity Checksum Changed        (high, lvl 5)
Rule 751   – Registry Value Entry Deleted                     (high, lvl 5)
Rule 752   – Registry Value Entry Added to the System         (high, lvl 5)
Rule 594   – Registry Key Integrity Checksum Changed          (high, lvl 5)
Rule 60106 – (misc low-value events)
Min-Level  – Only store/process alerts at Wazuh level ≥ 7
"""

import logging
from functools import lru_cache
from datetime import datetime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default noise filter definitions (seeded into DB on first run)
# ---------------------------------------------------------------------------

DEFAULT_FILTERS = [
    {
        'name': 'SonicWall IKEv2 Handshake Failures',
        'filter_type': 'rule_id',
        'filter_value': '4804',
        'action': 'suppress',
        'estimated_daily': 295000,
        'notes': (
            'IKEv2 Unable to find IKE SA — normal VPN client churn. '
            'These appear whenever a VPN client retransmits an IKE_SA_INIT '
            'after the gateway has already cleaned up the session. '
            'Not an indicator of attack unless volume spikes abnormally.'
        ),
    },
    {
        'name': 'SonicWall Generic Error Messages',
        'filter_type': 'rule_id',
        'filter_value': '4803',
        'action': 'suppress',
        'estimated_daily': 53000,
        'notes': (
            'Generic SonicWall error-level syslog events covering dozens '
            'of benign network conditions. Rule 4803 fires on a wide range '
            'of normal appliance operations and contributes ~7% of daily noise.'
        ),
    },
    {
        'name': 'Windows DCOM COM Permission Errors',
        'filter_type': 'rule_id',
        'filter_value': '61102',
        'action': 'suppress',
        'estimated_daily': 47000,
        'notes': (
            'Windows Event ID 10016 — COM server activation permission '
            'denied for service accounts (e.g. SQL Distributed Replay Client). '
            'Chronic Windows misconfig; not an active attack. '
            'Alert if volume increases > 5× baseline or on non-service accounts.'
        ),
    },
    {
        'name': 'TacticalRMM Service Events',
        'filter_type': 'rule_id',
        'filter_value': '61107',
        'action': 'suppress',
        'estimated_daily': 18000,
        'notes': (
            'TacticalRMM Agent Service terminated unexpectedly — occurs '
            'during normal RMM agent updates and network flaps. '
            'Low fidelity indicator on its own.'
        ),
    },
    {
        'name': 'Report Signature Summary Events',
        'filter_type': 'rule_id',
        'filter_value': '60608',
        'action': 'suppress',
        'estimated_daily': 14000,
        'notes': (
            'Routine summary signature events from endpoint AV/EDR products. '
            'No direct threat value; informational telemetry only.'
        ),
    },
    {
        'name': 'Software Protection Service (KMS)',
        'filter_type': 'rule_id',
        'filter_value': '60642',
        'action': 'suppress',
        'estimated_daily': 8800,
        'notes': (
            'Windows Software Protection Platform scheduled activation events. '
            'Routine and expected on any Windows system with volume licensing. '
            'NOTE: Separate from HackTool KMSpico alerts (rule 62123) which '
            'should always be surfaced.'
        ),
    },
    {
        'name': 'Registry FIM — Value Checksum Changed',
        'filter_type': 'rule_id',
        'filter_value': '750',
        'action': 'suppress',
        'estimated_daily': 9500,
        'notes': (
            'Registry value integrity checksum changed — extremely noisy '
            'during normal system updates and software installs. '
            'Review only if rule 550 (file FIM) also spikes on same agent.'
        ),
    },
    {
        'name': 'Registry FIM — Value Entry Deleted',
        'filter_type': 'rule_id',
        'filter_value': '751',
        'action': 'suppress',
        'estimated_daily': 5000,
        'notes': 'Registry value entry deleted — same noise rationale as rule 750.',
    },
    {
        'name': 'Registry FIM — Value Entry Added',
        'filter_type': 'rule_id',
        'filter_value': '752',
        'action': 'suppress',
        'estimated_daily': 9600,
        'notes': 'Registry value entry added — same noise rationale as rule 750.',
    },
    {
        'name': 'Registry FIM — Key Checksum Changed',
        'filter_type': 'rule_id',
        'filter_value': '594',
        'action': 'suppress',
        'estimated_daily': 8000,
        'notes': 'Registry key integrity checksum — baseline noise during updates.',
    },
    {
        'name': 'Misc Low-Value Events',
        'filter_type': 'rule_id',
        'filter_value': '60106',
        'action': 'suppress',
        'estimated_daily': 2000,
        'notes': 'Miscellaneous low-fidelity informational events.',
    },
    {
        'name': 'Minimum Alert Level — Store Only Level ≥ 7',
        'filter_type': 'min_level',
        'filter_value': '7',
        'action': 'suppress',
        'estimated_daily': 0,
        'notes': (
            'Do not store alerts below Wazuh rule level 7 (medium). '
            'Levels 1-6 are informational/debug and rarely indicate threats. '
            'This dramatically reduces DB writes without losing signal.'
        ),
    },
]

# ---------------------------------------------------------------------------
# Rule ID sets (for fast in-memory lookup)
# ---------------------------------------------------------------------------

# Rule IDs that are always suppressed by the default filter set
# (used when DB is unavailable or for quick pre-screen)
DEFAULT_SUPPRESSED_RULE_IDS = {
    '4804', '4803', '61102', '61107', '60608',
    '60642', '750', '751', '752', '594', '60106',
}

DEFAULT_MIN_LEVEL = 7


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------

def seed_default_filters(app):
    """
    Idempotent — insert default NoiseFilter records if they don't exist.
    Called once at app startup.
    """
    with app.app_context():
        from models import db, NoiseFilter
        try:
            for fd in DEFAULT_FILTERS:
                exists = NoiseFilter.query.filter_by(
                    name=fd['name'], is_system=True
                ).first()
                if not exists:
                    nf = NoiseFilter(
                        name=fd['name'],
                        filter_type=fd['filter_type'],
                        filter_value=fd['filter_value'],
                        action=fd['action'],
                        estimated_daily=fd.get('estimated_daily', 0),
                        notes=fd.get('notes', ''),
                        enabled=True,
                        is_system=True,
                    )
                    db.session.add(nf)
            db.session.commit()
            logger.info('NoiseFilter defaults seeded successfully')
        except Exception as exc:
            db.session.rollback()
            logger.error(f'Failed to seed noise filters: {exc}')


# ---------------------------------------------------------------------------
# Filter engine
# ---------------------------------------------------------------------------

def _load_active_filters(app=None):
    """Return list of active NoiseFilter dicts.  Returns hardcoded defaults
    if the DB is not available."""
    try:
        from models import NoiseFilter
        filters = NoiseFilter.query.filter_by(enabled=True).all()
        return [
            {
                'id':           f.id,
                'name':         f.name,
                'filter_type':  f.filter_type,
                'filter_value': f.filter_value,
                'action':       f.action,
            }
            for f in filters
        ]
    except Exception:
        # Fall back to hardcoded defaults
        return [
            {'id': None, 'name': fd['name'], 'filter_type': fd['filter_type'],
             'filter_value': fd['filter_value'], 'action': fd['action']}
            for fd in DEFAULT_FILTERS
        ]


def get_noise_exclusion_clause():
    """
    Return a list of OpenSearch query clauses suitable for use in a
    ``must_not`` block.  These exclude all alerts matching active suppress-
    action filters.

    Usage::
        must_not = get_noise_exclusion_clause()
        query = {"bool": {"filter": [...], "must_not": must_not}}
    """
    filters = _load_active_filters()
    rule_ids = []
    must_not = []
    min_level = None

    for f in filters:
        if f['action'] != 'suppress':
            continue
        ft = f['filter_type']
        fv = f['filter_value']

        if ft == 'rule_id':
            for rid in fv.split(','):
                rid = rid.strip()
                if rid.isdigit():
                    rule_ids.append(int(rid))
                else:
                    rule_ids.append(rid)

        elif ft == 'rule_group':
            must_not.append({'term': {'rule.groups': fv.strip()}})

        elif ft == 'min_level':
            try:
                val = int(fv.strip())
                # "min_level 7" means suppress level < 7 → must_not level < 7
                if min_level is None or val > min_level:
                    min_level = val
            except ValueError:
                pass

        elif ft == 'description_contains':
            must_not.append({'match_phrase': {'rule.description': fv.strip()}})

        elif ft == 'agent':
            must_not.append({'term': {'agent.name': fv.strip()}})

    if rule_ids:
        must_not.append({'terms': {'rule.id': rule_ids}})

    if min_level is not None:
        must_not.append({'range': {'rule.level': {'lt': min_level}}})

    return must_not


def should_store_alert(alert_source: dict) -> bool:
    """
    Fast pre-screen for use in the alert storage job.
    Returns False (→ skip) if the alert matches a suppress filter.

    ``alert_source`` is the ``_source`` dict from an OpenSearch hit.
    """
    rule  = alert_source.get('rule', {})
    level = rule.get('level', 0)
    rid   = str(rule.get('id', ''))

    # Min level check
    if level < DEFAULT_MIN_LEVEL:
        return False

    # Rule ID check
    if rid in DEFAULT_SUPPRESSED_RULE_IDS:
        return False

    # Try DB filters for any user-added rules
    try:
        from models import NoiseFilter
        user_filters = NoiseFilter.query.filter_by(
            enabled=True, filter_type='rule_id', action='suppress',
            is_system=False,
        ).all()
        for nf in user_filters:
            for v in nf.filter_value.split(','):
                if v.strip() == rid:
                    return False
    except Exception:
        pass

    return True


# ---------------------------------------------------------------------------
# Live analysis helper
# ---------------------------------------------------------------------------

def live_noise_analysis(hours: int = 24) -> dict:
    """
    Query OpenSearch for alert volume breakdown over the past ``hours``.
    Returns a dict suitable for the management UI.
    """
    try:
        from opensearch_api import OpenSearchAPI
        from datetime import timedelta

        api = OpenSearchAPI()
        if not api.client:
            return {'error': 'OpenSearch not available'}

        since = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S')

        # Total volume + top rules
        q = {
            'size': 0,
            'query': {'range': {'@timestamp': {'gte': since}}},
            'aggs': {
                'total_count': {'value_count': {'field': '@timestamp'}},
                'top_rules': {
                    'terms': {'field': 'rule.id', 'size': 20},
                    'aggs': {
                        'rule_desc': {'terms': {'field': 'rule.description', 'size': 1}},
                        'rule_level': {'terms': {'field': 'rule.level', 'size': 1}},
                    }
                },
                'by_level': {
                    'range': {
                        'field': 'rule.level',
                        'ranges': [
                            {'key': 'low',      'from': 1, 'to': 7},
                            {'key': 'medium',   'from': 7, 'to': 12},
                            {'key': 'high',     'from': 12, 'to': 15},
                            {'key': 'critical', 'from': 15},
                        ]
                    }
                }
            }
        }

        try:
            resp = api.client.search(index='wazuh-alerts-*', body=q, request_timeout=30)
        except Exception as exc:
            return {'error': str(exc)}

        aggs = resp.get('aggregations', {})

        # Total
        total = resp['hits']['total']['value']
        if resp['hits']['total']['relation'] == 'gte':
            total_label = f'{total:,}+'
        else:
            total_label = f'{total:,}'

        # By level
        level_counts = {}
        for b in aggs.get('by_level', {}).get('buckets', []):
            level_counts[b['key']] = b['doc_count']

        # Top rules
        suppressed_ids = DEFAULT_SUPPRESSED_RULE_IDS
        top_rules = []
        suppressed_total = 0

        for b in aggs.get('top_rules', {}).get('buckets', []):
            rid = str(b['key'])
            desc_buckets = b.get('rule_desc', {}).get('buckets', [])
            desc = desc_buckets[0]['key'] if desc_buckets else ''
            lvl_buckets  = b.get('rule_level', {}).get('buckets', [])
            lvl  = lvl_buckets[0]['key'] if lvl_buckets else 0
            count = b['doc_count']
            is_noise = rid in suppressed_ids or (isinstance(lvl, int) and lvl < DEFAULT_MIN_LEVEL)

            if is_noise:
                suppressed_total += count

            top_rules.append({
                'rule_id':    rid,
                'description':desc,
                'level':      lvl,
                'count':      count,
                'pct':        round(count / max(total, 1) * 100, 1),
                'is_noise':   is_noise,
            })

        # Estimate signal vs noise
        noise_pct  = round(suppressed_total / max(total, 1) * 100, 1)
        signal_pct = round(100 - noise_pct, 1)

        return {
            'hours':           hours,
            'total':           total,
            'total_label':     total_label,
            'noise_pct':       noise_pct,
            'signal_pct':      signal_pct,
            'suppressed_total':suppressed_total,
            'level_counts':    level_counts,
            'top_rules':       top_rules,
        }

    except Exception as exc:
        logger.error(f'live_noise_analysis error: {exc}', exc_info=True)
        return {'error': str(exc)}
