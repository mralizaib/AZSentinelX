import logging
import json
import datetime
import ipaddress
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import ConnectionError, AuthenticationException, RequestError
from config import Config

logger = logging.getLogger(__name__)


def _nested_value(source, path):
    """Read a dotted field from an OpenSearch document safely."""
    current = source
    for part in path.split('.'):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first_value(source, *paths):
    """Return the first non-empty value from a document."""
    for path in paths:
        value = _nested_value(source, path)
        if value not in (None, '', [], {}):
            return value
    return None


def _display_value(value, default='N/A'):
    """Convert archive values into safe, compact display strings."""
    if value in (None, '', [], {}):
        return default
    if isinstance(value, (list, tuple, set)):
        return ', '.join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _escape_wildcard_value(value):
    """Escape user input before placing it in an OpenSearch wildcard query."""
    return (
        '*'
        + str(value).strip()
        .replace('\\', '\\\\')
        .replace('*', '\\*')
        .replace('?', '\\?')
        + '*'
    )


def _is_ip_address(value):
    """Return whether a search value is a literal IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _append_strict_text_search(query, value, fields, wildcard_fields=None,
                               ip_fields=None):
    """
    Add one literal, relevance-preserving search clause.

    The old search used ``multi_match`` with AUTO fuzziness and expanded
    friendly words into unrelated synonyms.  That is useful for discovery,
    but it also makes a precise device/IP search match records that contain
    only a vaguely similar term.  A phrase match keeps all entered words
    together; wildcard queries are retained only for keyword fields so names
    and descriptions can still be searched by a meaningful substring.
    IP values use exact term clauses for structured IP fields.
    """
    normalized = str(value or '').strip()
    if not normalized:
        return

    should = []
    is_ip_query = _is_ip_address(normalized)
    if is_ip_query:
        for field in ip_fields or []:
            should.append({"term": {field: normalized}})
            should.append({"match_phrase": {field: normalized}})
        # An IP can also be present only inside the raw syslog/alert payload.
        # Phrase matching avoids wildcard substring matches such as searching
        # for 10.0.0.1 and returning 110.0.0.10.
        for field in fields:
            if field not in (ip_fields or []):
                should.append({"match_phrase": {field: normalized}})
    else:
        for field in fields:
            should.append({"match_phrase": {field: normalized}})

    if not is_ip_query:
        wildcard_value = _escape_wildcard_value(normalized)
        for field in wildcard_fields or []:
            should.append({
                "wildcard": {
                    field: {
                        "value": wildcard_value,
                        "case_insensitive": True,
                    }
                }
            })

    if should:
        query["bool"]["must"].append({
            "bool": {
                "should": should,
                "minimum_should_match": 1,
            }
        })


def _append_exact_field_filter(query, value, fields):
    """Require one of the supplied fields to equal a decoder name."""
    normalized = str(value or '').strip()
    if not normalized:
        return

    query["bool"]["filter"].append({
        "bool": {
            "should": [
                {
                    "term": {
                        field: {
                            "value": normalized,
                            "case_insensitive": True,
                        }
                    }
                }
                for field in fields
            ],
            "minimum_should_match": 1,
        }
    })


def _normalize_syslog_hit(hit, server_key, server_name, server_timezone):
    """Expose common network/syslog fields without changing the raw source."""
    source = hit.get('_source', {}) or {}
    event_data = source.get('data') if isinstance(source.get('data'), dict) else {}
    decoder = _first_value(
        source,
        'decoder.name',
        'data.decoder.name',
        'rule.decoder',
        'decoder',
    )
    decoder_parent = _first_value(source, 'decoder.parent', 'data.decoder.parent')
    if isinstance(decoder, dict):
        decoder = _first_value(decoder, 'name', 'parent')
    decoder_name = _display_value(decoder)
    if decoder_name == 'N/A' and decoder_parent not in (None, ''):
        decoder_name = _display_value(decoder_parent)

    timestamp = _first_value(source, '@timestamp', 'timestamp', 'predecoder.timestamp')
    source_device_ip = _first_value(
        source,
        'source.ip',
        'data.srcip',
        'data.src_ip',
        'data.source.ip',
        'srcip',
        'src_ip',
        'observer.ip',
        'host.ip',
        'agent.ip',
    )
    destination_ip = _first_value(
        source,
        'destination.ip',
        'data.dstip',
        'data.dst_ip',
        'data.dest_ip',
        'data.destination.ip',
        'dstip',
        'dst_ip',
        'dest_ip',
    )
    device_hostname = _first_value(
        source,
        'host.name',
        'device.hostname',
        'device.name',
        'predecoder.hostname',
        'data.hostname',
        'hostname',
        'agent.name',
    )
    message = _first_value(
        source,
        'full_log',
        'message',
        'syslog.message',
        'event.original',
        'data.message',
    )
    rule = source.get('rule') if isinstance(source.get('rule'), dict) else {}
    rule_id = _first_value(source, 'rule.id', 'data.rule.id')
    rule_level = _first_value(source, 'rule.level', 'data.rule.level')
    rule_description = _first_value(source, 'rule.description', 'data.rule.description')
    operation = _first_value(
        source,
        'operation',
        'event.action',
        'data.operation',
    )
    event_type_name = _first_value(
        source,
        'type',
        'event.type',
        'data.type',
    )
    event_name = _first_value(
        source,
        'name',
        'event.name',
        'data.name',
    )

    return {
        'id': hit.get('_id'),
        'index': hit.get('_index'),
        'score': hit.get('_score'),
        'server_key': server_key,
        'server_name': server_name,
        'server_timezone': server_timezone,
        'event_type': 'syslog',
        'event_category': 'Syslog / Network Device',
        'timestamp': timestamp,
        'source_device_ip': _display_value(source_device_ip),
        'destination_ip': _display_value(destination_ip),
        'device_hostname': _display_value(device_hostname),
        'syslog_message': _display_value(message),
        'decoder_name': decoder_name,
        'decoder_parent': _display_value(decoder_parent),
        'rule_id': _display_value(rule_id),
        'rule_level': rule_level if rule_level not in (None, '') else 0,
        'rule_description': _display_value(rule_description),
        # Keep the structured payload available to the UI. Syscollector
        # records often have no human-readable full_log field; their useful
        # content lives in data alongside operation/type.
        'event_operation': _display_value(operation),
        'event_type_name': _display_value(event_type_name),
        'event_name': _display_value(event_name),
        'event_data': event_data,
        'source': source,
    }


class OpenSearchAPI:
    def __init__(self, server_key=None):
        if server_key is None:
            try:
                from flask import has_request_context, session
                server_key = session.get('wazuh_server', 'primary') if has_request_context() else 'primary'
            except RuntimeError:
                server_key = 'primary'
        self.server_key = server_key if server_key in ('primary', 'secondary') else 'primary'
        server = Config.get_server(self.server_key)
        self.server_name = server['name']
        self.server_timezone = server.get('timezone', 'UTC')
        self.host = server['opensearch_url']
        self.username = server['opensearch_user']
        self.password = server['opensearch_password']
        self.verify_ssl = server['opensearch_verify_ssl']
        self.index_pattern = Config.OPENSEARCH_INDEX_PATTERN
        self.client = None
        self.archives_index_pattern = getattr(
            Config,
            'OPENSEARCH_ARCHIVES_INDEX_PATTERN',
            'wazuh-archives-*'
        )
        self._connect()
    
    def _connect(self):
        """Connect to OpenSearch instance"""
        try:
            self.client = OpenSearch(
                hosts=[self.host],
                http_auth=(self.username, self.password),
                use_ssl=True if self.host.startswith('https') else False,
                verify_certs=self.verify_ssl,
                connection_class=RequestsHttpConnection,
                timeout=60,
            )
            if self.client.ping():
                logger.info("Successfully connected to OpenSearch")
                return True
            else:
                logger.error("Failed to connect to OpenSearch, ping failed")
                return False
        except (ConnectionError, AuthenticationException) as e:
            logger.error(f"Failed to connect to OpenSearch: {str(e)}")
            return False
        
    def search_alerts(self, severity_levels=None, start_time=None, end_time=None, 
                      limit=100, offset=0, sort_field="_score", sort_order="desc", 
                      additional_filters=None, decoder_query=None,
                      normalize_syslog=False):
        """
        Search for alerts in OpenSearch based on filters
        """
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        
        try:
            # Build the query
            query = {
                "bool": {
                    "must": [],
                    "filter": [],
                }
            }
            
            # Define Misc Events criteria (Rule IDs and descriptions)
            misc_events_filter = {
                "bool": {
                    "should": [
                        {"terms": {"rule.id": [750, 60642, 752, 550, 60106]}},
                        {"match_phrase": {"rule.description": "SonicWall warning messages"}},
                        {"match_phrase": {"rule.description": "SonicWall error messages"}},
                        {"match_phrase": {"rule.description": "Integrity checksum changed"}},
                        {"match_phrase": {"rule.description": "Registry value integrity checksum changed"}}
                    ],
                    "minimum_should_match": 1
                }
            }

            # Map severity keywords to Wazuh/OpenSearch levels
            severity_map = {
                'low': {"gte": 1, "lte": 6},
                'medium': {"gte": 7, "lte": 11},
                'high': {"gte": 12, "lte": 14},
                'critical': {"gte": 15, "lte": 100}
            }
            
            # Add time range filter if specified
            if start_time and end_time:
                query["bool"]["filter"].append({
                    "range": {
                        "@timestamp": {
                            "gte": start_time,
                            "lte": end_time
                        }
                    }
                })
            
            # Add severity level filters
            if severity_levels:
                level_ranges = []
                for severity in severity_levels:
                    severity = severity.lower()
                    if severity in severity_map:
                        # Exclude Misc Events from Low and Medium
                        if severity in ['low', 'medium']:
                            level_ranges.append({
                                "bool": {
                                    "must": [
                                        {"range": {"rule.level": severity_map[severity]}}
                                    ],
                                    "must_not": [misc_events_filter]
                                }
                            })
                        else:
                            level_ranges.append({
                                "range": {
                                    "rule.level": severity_map[severity]
                                }
                            })
                    elif severity == 'fim':
                        # Special handling for FIM - filter by specific rule IDs
                        level_ranges.append({
                            "terms": {
                                "rule.id": [553, 554]
                            }
                        })
                    elif severity == 'events':
                        # Special handling for Misc Events
                        level_ranges.append(misc_events_filter)
                
                if level_ranges:
                    # Use filter instead of should for more precise filtering
                    if len(level_ranges) == 1:
                        query["bool"]["filter"].extend(level_ranges)
                    else:
                        query["bool"]["filter"].append({
                            "bool": {
                                "should": level_ranges,
                                "minimum_should_match": 1
                            }
                        })
            
            # Add additional filters if specified
            if additional_filters:
                for field, value in additional_filters.items():
                    if field == 'search_query' and value:
                        # Use one literal search policy for every alert field.
                        # The previous mixture of multi_match, fuzzy analysis,
                        # and broad wildcards could surface an unrelated
                        # Windows event when searching for a short term such
                        # as "RDP".
                        _append_strict_text_search(
                            query,
                            value,
                            fields=[
                                "agent.name",
                                "agent.ip",
                                "host.name",
                                "host.ip",
                                "device.name",
                                "device.hostname",
                                "rule.description",
                                "rule.groups",
                                "full_log",
                                "message",
                                "data.win.eventdata.targetUserName",
                                "data.win.eventdata.subjectUserName",
                                "data.win.eventdata.logonId",
                                "data.win.eventdata.logonType",
                                "data.win.eventdata.ipAddress",
                                "data.win.eventdata.ipPort",
                                "data.win.eventdata.status",
                                "data.win.eventdata.subStatus",
                                "data.win.eventdata.destinationUserName",
                                "data.win.eventdata.sourceUserName",
                                "data.win.eventdata.logonProcessName",
                                "data.win.eventdata.authenticationPackageName",
                                "data.win.eventdata.parentImage",
                                "data.win.eventdata.commandLine",
                                "data.win.eventdata.serviceName",
                                "syscheck.uname_after",
                                "syscheck.path",
                            ],
                            wildcard_fields=[
                                "agent.name",
                                "agent.ip",
                                "host.name",
                                "host.ip",
                                "device.name",
                                "device.hostname",
                                "rule.description",
                                "rule.groups",
                                "full_log",
                                "message",
                                "data.win.eventdata.targetUserName",
                                "data.win.eventdata.subjectUserName",
                                "data.win.eventdata.destinationUserName",
                                "data.win.eventdata.sourceUserName",
                                "data.win.eventdata.commandLine",
                                "data.win.eventdata.serviceName",
                                "syscheck.uname_after",
                                "syscheck.path",
                            ],
                            ip_fields=[
                                "agent.ip",
                                "host.ip",
                                "data.win.eventdata.ipAddress",
                            ],
                        )
                    elif field == 'rule.id' and isinstance(value, list):
                        # Handle list values for rule IDs (like FIM)
                        query["bool"]["filter"].append({
                            "terms": {
                                field: value
                            }
                        })
                    else:
                        # Regular term filter for other fields
                        query["bool"]["filter"].append({
                            "term": {
                                field: value
                            }
                        })

            if decoder_query:
                _append_exact_field_filter(
                    query,
                    decoder_query,
                    [
                        "decoder.name",
                        "decoder.parent",
                        "data.decoder.name",
                        "data.decoder.parent",
                        "rule.decoder",
                    ],
                )
            
            # Build the search body
            search_body = {
                "query": query,
                "from": offset,
                "size": limit,
                "sort": [
                    {sort_field: {"order": sort_order}}
                ]
            }
            
            # Execute the search
            response = self.client.search(
                body=search_body,
                index=self.index_pattern
            )
            
            # Format the results
            hits = response["hits"]["hits"]
            total = response["hits"]["total"]["value"]
            
            results = []
            for hit in hits:
                # The Syslog filter is backed by the regular alert index on
                # installations where syscollector events are indexed there.
                # Normalize those hits exactly like archive hits so the
                # frontend can render their structured data as a readable log
                # instead of dumping {"data": ...} into the table.
                if decoder_query or normalize_syslog:
                    normalized = _normalize_syslog_hit(
                        hit,
                        self.server_key,
                        self.server_name,
                        self.server_timezone,
                    )
                    normalized.update({
                        "id": hit["_id"],
                        "index": hit["_index"],
                        "score": hit["_score"],
                    })
                    results.append(normalized)
                else:
                    results.append({
                        "id": hit["_id"],
                        "index": hit["_index"],
                        "score": hit["_score"],
                        "server_key": self.server_key,
                        "server_name": self.server_name,
                        "server_timezone": self.server_timezone,
                        "source": hit["_source"]
                    })
            
            return {
                "total": total,
                "results": results,
                "server_key": self.server_key,
                "server_name": self.server_name,
                "server_timezone": self.server_timezone,
                "request": search_body  # Include the request for debugging
            }
            
        except RequestError as e:
            logger.error(f"Error in search query: {str(e)}")
            return {"error": f"Query error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error searching alerts: {str(e)}")
            return {"error": str(e)}

    def search_syslog_events(
        self,
        start_time=None,
        end_time=None,
        search_query=None,
        decoder_query=None,
        limit=100,
        offset=0,
        sort_field='@timestamp',
        sort_order='desc',
    ):
        """Search decoded network/syslog events in Wazuh archive indices."""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}

        try:
            query = {"bool": {"must": [], "filter": []}}

            if start_time and end_time:
                query["bool"]["filter"].append({
                    "range": {
                        "@timestamp": {
                            "gte": start_time,
                            "lte": end_time,
                        }
                    }
                })

            # With a search term, the strict text clause below is the source
            # of truth. Do not require a decoder marker first: some archive
            # records contain only full_log/message, and that would hide valid
            # OpenVPN or vendor-device matches. With no search term, retain
            # the Syslog shape checks so the unfiltered view does not become
            # a dump of every non-log archive document.
            if not search_query and not decoder_query:
                query["bool"]["filter"].append({
                    "bool": {
                        "should": [
                            {"exists": {"field": "decoder.name"}},
                            {"exists": {"field": "decoder.parent"}},
                            {"exists": {"field": "data.decoder.name"}},
                            {"exists": {"field": "data.decoder.parent"}},
                            {"exists": {"field": "rule.decoder"}},
                            {"exists": {"field": "predecoder.program_name"}},
                        ],
                        "minimum_should_match": 1,
                    }
                })
                query["bool"]["filter"].append({
                    "bool": {
                        "should": [
                            {"exists": {"field": "full_log"}},
                            {"exists": {"field": "message"}},
                            {"exists": {"field": "syslog.message"}},
                            {"exists": {"field": "event.original"}},
                        ],
                        "minimum_should_match": 1,
                    }
                })

            decoder_fields = [
                "decoder.name",
                "decoder.parent",
                "data.decoder.name",
                "data.decoder.parent",
                "rule.decoder",
                "predecoder.program_name",
            ]

            if decoder_query:
                _append_exact_field_filter(
                    query,
                    decoder_query,
                    decoder_fields,
                )

            if search_query:
                _append_strict_text_search(
                    query,
                    search_query,
                    [
                        "agent.name",
                        "agent.ip",
                        "host.name",
                        "host.ip",
                        "device.name",
                        "device.hostname",
                        "source.ip",
                        "destination.ip",
                        "srcip",
                        "dstip",
                        "data.srcip",
                        "data.dstip",
                        "data.src_ip",
                        "data.dst_ip",
                        "predecoder.hostname",
                        "predecoder.program_name",
                        "decoder.name",
                        "decoder.parent",
                        "rule.description",
                        "full_log",
                        "message",
                        "syslog.message",
                        "event.original",
                        "location",
                    ],
                    wildcard_fields=[
                        "agent.name",
                        "agent.ip",
                        "host.name",
                        "host.ip",
                        "device.name",
                        "device.hostname",
                        "source.ip",
                        "destination.ip",
                        "srcip",
                        "dstip",
                        "data.srcip",
                        "data.dstip",
                        "data.src_ip",
                        "data.dst_ip",
                        "predecoder.hostname",
                        "predecoder.program_name",
                        "decoder.name",
                        "decoder.parent",
                        "rule.description",
                        "full_log",
                        "message",
                        "syslog.message",
                        "event.original",
                        "location",
                    ],
                    ip_fields=[
                        "agent.ip",
                        "host.ip",
                        "source.ip",
                        "destination.ip",
                        "srcip",
                        "dstip",
                        "data.srcip",
                        "data.dstip",
                        "data.src_ip",
                        "data.dst_ip",
                    ],
                )

            search_body = {
                "query": query,
                "from": offset,
                "size": limit,
                "sort": [{sort_field: {"order": sort_order}}],
            }
            response = self.client.search(
                body=search_body,
                index=self.archives_index_pattern,
            )
            hits = response.get("hits", {}).get("hits", [])
            total_value = response.get("hits", {}).get("total", 0)
            total = total_value.get("value", 0) if isinstance(total_value, dict) else total_value

            return {
                "total": total,
                "results": [
                    _normalize_syslog_hit(
                        hit,
                        self.server_key,
                        self.server_name,
                        self.server_timezone,
                    )
                    for hit in hits
                ],
                "server_key": self.server_key,
                "server_name": self.server_name,
                "server_timezone": self.server_timezone,
                "request": search_body,
            }
        except RequestError as e:
            logger.error(f"Error searching syslog archive: {str(e)}")
            return {"error": f"Query error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error searching syslog archive: {str(e)}")
            return {"error": str(e)}
    
    def search_fim_events(self, start_time, end_time, agent_names=None, paths=None,
                          file_names=None, file_extensions=None, limit=200):
        """
        Search for File Integrity Monitoring (FIM/syscheck) events with strict filtering.

        Args:
            start_time: ISO timestamp for range start
            end_time: ISO timestamp for range end
            agent_names: list of agent.name values to match (required for FIM)
            paths: list of syscheck.path prefixes to match (required for FIM)
            file_names: optional list of file name filters
            file_extensions: optional list of extension filters
            limit: max results to return

        Returns:
            dict with 'total' and 'results'
        """
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}

        try:
            must_filters = [
                {
                    "range": {
                        "@timestamp": {"gte": start_time, "lte": end_time}
                    }
                },
                # Match syscheck group OR the standard FIM rule IDs (553/554) so that
                # events visible on the dashboard are always captured here too.
                {
                    "bool": {
                        "should": [
                            {"term": {"rule.groups": "syscheck"}},
                            {"terms": {"rule.id": ["550", "551", "552", "553", "554", "555",
                                                   550, 551, 552, 553, 554, 555]}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            ]

            # Agent name filter — case-insensitive matching.
            # Also uses a leading/trailing wildcard so that names with a domain
            # suffix (e.g. "ITSUPPORT-LHR.domain.local") still match when the
            # user configured just "ITSUPPORT-LHR".
            if agent_names:
                agent_clauses = []
                for name in agent_names:
                    # Exact matches (case variants)
                    agent_clauses.append({"term": {"agent.name": name}})
                    if name.lower() != name:
                        agent_clauses.append({"term": {"agent.name": name.lower()}})
                    if name.upper() != name:
                        agent_clauses.append({"term": {"agent.name": name.upper()}})
                    # Case-insensitive exact wildcard
                    agent_clauses.append({
                        "wildcard": {
                            "agent.name": {
                                "value": name,
                                "case_insensitive": True
                            }
                        }
                    })
                    # Substring wildcard — catches "ITSUPPORT-LHR.domain.local" etc.
                    agent_clauses.append({
                        "wildcard": {
                            "agent.name": {
                                "value": f"*{name}*",
                                "case_insensitive": True
                            }
                        }
                    })
                must_filters.append({
                    "bool": {"should": agent_clauses, "minimum_should_match": 1}
                })

            # Path filter — match if syscheck.path starts with any configured path.
            # Normalise both forward-slash and backslash variants so Windows paths
            # like "C:\Users\Desktop" match however they are stored in OpenSearch.
            if paths:
                path_clauses = []
                for p in paths:
                    # Strip trailing separators (both slash types)
                    p_clean = p.rstrip('/').rstrip('\\')
                    # Build both slash variants for Windows compatibility
                    p_fwd = p_clean.replace('\\', '/')
                    p_bck = p_clean.replace('/', '\\')
                    for variant in {p_clean, p_fwd, p_bck}:
                        path_clauses.append({"prefix": {"syscheck.path": variant}})
                        path_clauses.append({"term": {"syscheck.path": variant}})
                        path_clauses.append({
                            "wildcard": {
                                "syscheck.path": {
                                    "value": f"{variant}*",
                                    "case_insensitive": True
                                }
                            }
                        })
                must_filters.append({
                    "bool": {"should": path_clauses, "minimum_should_match": 1}
                })

            # Optional file name filter (match against the last segment of syscheck.path)
            if file_names:
                fn_clauses = [
                    {"wildcard": {"syscheck.path": {"value": f"*{fn}", "case_insensitive": True}}}
                    for fn in file_names
                ]
                must_filters.append({"bool": {"should": fn_clauses, "minimum_should_match": 1}})

            # Optional file extension filter
            if file_extensions:
                ext_clauses = []
                for ext in file_extensions:
                    e = ext if ext.startswith('.') else f'.{ext}'
                    ext_clauses.append({
                        "wildcard": {"syscheck.path": {"value": f"*{e}", "case_insensitive": True}}
                    })
                must_filters.append({"bool": {"should": ext_clauses, "minimum_should_match": 1}})

            search_body = {
                "query": {"bool": {"filter": must_filters}},
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }

            response = self.client.search(body=search_body, index=self.index_pattern)
            hits = response["hits"]["hits"]
            total = response["hits"]["total"]["value"]

            results = []
            for hit in hits:
                results.append({
                    "id": hit["_id"],
                    "index": hit["_index"],
                    "score": hit.get("_score"),
                    "server_key": self.server_key,
                    "server_name": self.server_name,
                    "server_timezone": self.server_timezone,
                    "source": hit["_source"]
                })

            return {
                "total": total,
                "results": results,
                "server_key": self.server_key,
                "server_name": self.server_name,
                "server_timezone": self.server_timezone,
            }

        except Exception as e:
            logger.error(f"Error searching FIM events: {str(e)}")
            return {"error": str(e)}

    def get_fim_agents_diagnostic(self, hours=4):
        """
        Return a list of agent names and sample paths that have FIM/syscheck
        events in the last `hours` hours, with NO agent/path filter applied.
        Used only for diagnostic logging when a filtered search returns 0 results.
        """
        if not self.client:
            if not self._connect():
                return []
        try:
            import datetime as _dt
            now = _dt.datetime.utcnow()
            start = (now - _dt.timedelta(hours=hours)).isoformat()
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": start, "lte": now.isoformat()}}},
                            {"bool": {
                                "should": [
                                    {"term": {"rule.groups": "syscheck"}},
                                    {"terms": {"rule.id": [
                                        "550","551","552","553","554","555",
                                        550, 551, 552, 553, 554, 555
                                    ]}}
                                ],
                                "minimum_should_match": 1
                            }}
                        ]
                    }
                },
                "aggs": {
                    "agents": {
                        "terms": {"field": "agent.name", "size": 30},
                        "aggs": {
                            "sample_paths": {
                                "terms": {"field": "syscheck.path", "size": 5}
                            }
                        }
                    }
                }
            }
            resp = self.client.search(body=body, index=self.index_pattern)
            buckets = resp.get("aggregations", {}).get("agents", {}).get("buckets", [])
            result = []
            for b in buckets:
                paths = [p["key"] for p in
                         b.get("sample_paths", {}).get("buckets", [])]
                result.append({
                    "agent_name": b["key"],
                    "fim_event_count": b["doc_count"],
                    "sample_paths": paths,
                })
            return result
        except Exception as e:
            logger.error(f"FIM diagnostic aggregation error: {e}")
            return []

    def get_alert_by_id(self, alert_id, index=None):
        """Get a specific alert by ID"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        
        try:
            if index:
                response = self.client.get(index=index, id=alert_id)
            else:
                # Search across the index pattern
                search_body = {
                    "query": {
                        "term": {
                            "_id": alert_id
                        }
                    }
                }
                
                response = self.client.search(
                    body=search_body,
                    index=self.index_pattern
                )
                
                if response["hits"]["total"]["value"] > 0:
                    return response["hits"]["hits"][0]
                else:
                    return {"error": f"Alert with ID {alert_id} not found"}
            
            return response
        except Exception as e:
            logger.error(f"Error getting alert: {str(e)}")
            return {"error": str(e)}
    
    def get_alert_count_by_severity(self, start_time=None, end_time=None):
        """Get alert counts grouped by severity level"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        
        try:
            # Build the query
            query = {
                "bool": {
                    "filter": []
                }
            }
            
            # Add time range filter if specified
            if start_time and end_time:
                query["bool"]["filter"].append({
                    "range": {
                        "@timestamp": {
                            "gte": start_time,
                            "lte": end_time
                        }
                    }
                })
            
            # Build the search body with aggregation
            search_body = {
                "size": 0,  # We only want aggregation results
                "query": query,
                "aggs": {
                    "severity_counts": {
                        "range": {
                            "field": "rule.level",
                            "ranges": [
                                {"to": 1, "key": "none"},            # Level 0
                                {"from": 1, "to": 7, "key": "low"},  # Levels 1-6
                                {"from": 7, "to": 12, "key": "medium"},  # Levels 7-11
                                {"from": 12, "to": 15, "key": "high"},   # Levels 12-14
                                {"from": 15, "key": "critical"}       # Level 15+
                            ]
                        }
                    },
                    "fim_counts": {
                        "terms": {
                            "field": "rule.id",
                            "include": [553, 554]
                        }
                    },
                    "misc_events_counts": {
                        "filter": {
                            "bool": {
                                "should": [
                                    # Suppressed rule IDs — noisy/informational rules excluded from security metrics
                                    {"terms": {"rule.id": [
                                        750,   # Software protection service scheduled successfully
                                        60642, # Registry Value Entry Deleted
                                        752,   # Registry Value Integrity Checksum Changed
                                        550,   # Windows System error event
                                        60106, # Integrity checksum changed (variant)
                                        4804,  # Windows audit failure event
                                        60104, # Integrity checksum changed
                                        61102, # SonicWall error message
                                        4803,  # Summary event of report's signatures
                                        60608, # Registry Value Entry Added
                                    ]}},
                                    {"match_phrase": {"rule.description": "SonicWall warning messages"}},
                                    {"match_phrase": {"rule.description": "SonicWall error messages"}},
                                    {"match_phrase": {"rule.description": "Integrity checksum changed"}},
                                    {"match_phrase": {"rule.description": "Registry value integrity checksum changed"}}
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        "aggs": {
                            "severity_breakdown": {
                                "range": {
                                    "field": "rule.level",
                                    "ranges": [
                                        {"from": 1, "to": 7, "key": "low"},
                                        {"from": 7, "to": 12, "key": "medium"}
                                    ]
                                }
                            }
                        }
                    }
                }
            }
            
            # Execute the search
            response = self.client.search(
                body=search_body,
                index=self.index_pattern
            )
            
            # Format the results
            buckets = response["aggregations"]["severity_counts"]["buckets"]
            
            result = {}
            for bucket in buckets:
                result[bucket["key"]] = bucket["doc_count"]
            
            # Add FIM count
            fim_buckets = response["aggregations"]["fim_counts"]["buckets"]
            fim_count = sum(bucket["doc_count"] for bucket in fim_buckets)
            result["fim"] = fim_count

            # Add Misc Events count
            misc_aggs = response["aggregations"]["misc_events_counts"]
            misc_count = misc_aggs["doc_count"]
            result["events"] = misc_count
            
            # Subtract Misc Events from Low and Medium counts for accurate display
            misc_low = 0
            misc_medium = 0
            for b in misc_aggs["severity_breakdown"]["buckets"]:
                if b["key"] == "low": misc_low = b["doc_count"]
                if b["key"] == "medium": misc_medium = b["doc_count"]
            
            result["low"] = max(0, result["low"] - misc_low)
            result["medium"] = max(0, result["medium"] - misc_medium)
            
            return result
        except Exception as e:
            logger.error(f"Error getting alert counts: {str(e)}")
            return {"error": str(e)}
    
    def get_high_severity_by_threat_type(self, start_time=None, end_time=None):
        """Get high and critical severity alerts grouped by threat type (rule.groups) and locations"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        
        try:
            # Default to last 24 hours if not specified
            if not end_time:
                end_time = datetime.datetime.utcnow().isoformat()
            if not start_time:
                start_time = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).isoformat()
            
            # Build the query for high and critical severity events (levels 12-14 and 15+)
            query = {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lte": end_time
                                }
                            }
                        }
                    ],
                    "should": [
                        {
                            "range": {
                                "rule.level": {
                                    "gte": 12,
                                    "lte": 14  # High severity (levels 12-14)
                                }
                            }
                        },
                        {
                            "range": {
                                "rule.level": {
                                    "gte": 15  # Critical severity (level 15+)
                                }
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }
            
            # Build the search body with aggregations
            search_body = {
                "size": 0,  # We only want aggregation results
                "query": query,
                "aggs": {
                    "threat_types": {
                        "terms": {
                            "field": "rule.groups",
                            "size": 10
                        }
                    },
                    "locations": {
                        "terms": {
                            "field": "agent.labels.location.set",
                            "size": 10
                        }
                    }
                }
            }
            
            # Execute the search
            response = self.client.search(
                body=search_body,
                index=self.index_pattern
            )
            
            # Process threat types
            threat_type_buckets = response['aggregations']['threat_types']['buckets']
            threat_types = []
            
            for bucket in threat_type_buckets:
                threat_types.append({
                    "name": bucket['key'],
                    "count": bucket['doc_count']
                })
            
            # Process locations
            location_buckets = response['aggregations']['locations']['buckets']
            locations = []
            
            for bucket in location_buckets:
                locations.append({
                    "name": bucket['key'],
                    "count": bucket['doc_count']
                })
            
            return {
                "threat_types": threat_types,
                "locations": locations
            }
            
        except Exception as e:
            logger.error(f"Error getting high severity threats by type: {str(e)}")
            return {"error": str(e)}
    
    def get_alerts_by_agent(self, severity_levels=None, start_time=None, end_time=None, limit=25):
        """
        Aggregate alert counts grouped by agent name and IP, with per-severity breakdown.
        Returns top N agents sorted by total alert count.
        """
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        try:
            severity_map = {
                'low':      {"gte": 1,  "lte": 6},
                'medium':   {"gte": 7,  "lte": 11},
                'high':     {"gte": 12, "lte": 14},
                'critical': {"gte": 15, "lte": 100},
            }
            filters = []
            if start_time and end_time:
                filters.append({"range": {"@timestamp": {"gte": start_time, "lte": end_time}}})
            if severity_levels:
                ranges = [{"range": {"rule.level": severity_map[s]}}
                          for s in severity_levels if s in severity_map]
                if ranges:
                    filters.append({"bool": {"should": ranges, "minimum_should_match": 1}})

            search_body = {
                "size": 0,
                "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
                "aggs": {
                    "by_agent": {
                        "terms": {"field": "agent.name", "size": limit, "order": {"_count": "desc"}},
                        "aggs": {
                            "agent_ip": {"terms": {"field": "agent.ip", "size": 1}},
                            "critical": {"filter": {"range": {"rule.level": {"gte": 15}}}},
                            "high":     {"filter": {"range": {"rule.level": {"gte": 12, "lte": 14}}}},
                            "medium":   {"filter": {"range": {"rule.level": {"gte": 7,  "lte": 11}}}},
                            "low":      {"filter": {"range": {"rule.level": {"gte": 1,  "lte": 6}}}},
                            "top_rules": {
                                "terms": {"field": "rule.description", "size": 3}
                            }
                        }
                    }
                }
            }
            response = self.client.search(body=search_body, index=self.index_pattern)
            agents = []
            for bucket in response["aggregations"]["by_agent"]["buckets"]:
                ip_buckets = bucket.get("agent_ip", {}).get("buckets", [])
                ip = ip_buckets[0]["key"] if ip_buckets else "N/A"
                top_rules = [r["key"] for r in bucket.get("top_rules", {}).get("buckets", [])]
                agents.append({
                    "agent_name": bucket["key"],
                    "agent_ip":   ip,
                    "total":      bucket["doc_count"],
                    "critical":   bucket["critical"]["doc_count"],
                    "high":       bucket["high"]["doc_count"],
                    "medium":     bucket["medium"]["doc_count"],
                    "low":        bucket["low"]["doc_count"],
                    "top_rules":  top_rules,
                })
            return {"agents": agents, "total_agents": len(agents)}
        except Exception as e:
            logger.error(f"Error in get_alerts_by_agent: {str(e)}")
            return {"error": str(e)}

    def get_alerts_by_rule(self, severity_levels=None, start_time=None, end_time=None, limit=20):
        """
        Aggregate alert counts grouped by rule description and ID.
        Returns top N rules sorted by count.
        """
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        try:
            severity_map = {
                'low':      {"gte": 1,  "lte": 6},
                'medium':   {"gte": 7,  "lte": 11},
                'high':     {"gte": 12, "lte": 14},
                'critical': {"gte": 15, "lte": 100},
            }
            filters = []
            if start_time and end_time:
                filters.append({"range": {"@timestamp": {"gte": start_time, "lte": end_time}}})
            if severity_levels:
                ranges = [{"range": {"rule.level": severity_map[s]}}
                          for s in severity_levels if s in severity_map]
                if ranges:
                    filters.append({"bool": {"should": ranges, "minimum_should_match": 1}})

            search_body = {
                "size": 0,
                "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
                "aggs": {
                    "by_rule": {
                        "terms": {"field": "rule.id", "size": limit, "order": {"_count": "desc"}},
                        "aggs": {
                            "description": {"terms": {"field": "rule.description", "size": 1}},
                            "level":       {"terms": {"field": "rule.level",       "size": 1}},
                            "agents_hit":  {"terms": {"field": "agent.name",       "size": 5}},
                        }
                    }
                }
            }
            response = self.client.search(body=search_body, index=self.index_pattern)
            rules = []
            for bucket in response["aggregations"]["by_rule"]["buckets"]:
                desc_buckets  = bucket.get("description", {}).get("buckets", [])
                level_buckets = bucket.get("level",       {}).get("buckets", [])
                agent_buckets = bucket.get("agents_hit",  {}).get("buckets", [])
                rules.append({
                    "rule_id":     bucket["key"],
                    "description": desc_buckets[0]["key"]  if desc_buckets  else "N/A",
                    "level":       level_buckets[0]["key"] if level_buckets else "N/A",
                    "count":       bucket["doc_count"],
                    "agents":      [a["key"] for a in agent_buckets],
                })
            return {"rules": rules, "total_rules": len(rules)}
        except Exception as e:
            logger.error(f"Error in get_alerts_by_rule: {str(e)}")
            return {"error": str(e)}

    def get_indices(self, pattern="wazuh-*"):
        """Get statistics for indices matching a pattern"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        try:
            # Use cat.indices for readable statistics
            indices = self.client.cat.indices(index=pattern, format="json", h="index,status,health,docs.count,pri.store.size")
            return indices
        except Exception as e:
            logger.error(f"Error getting indices stats: {str(e)}")
            return {"error": str(e)}

    def delete_index(self, index_name):
        """Delete a specific index"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        try:
            response = self.client.indices.delete(index=index_name)
            return response
        except Exception as e:
            logger.error(f"Error deleting index {index_name}: {str(e)}")
            return {"error": str(e)}

    def get_node_disk_stats(self):
        """Get disk usage statistics from the OpenSearch/Wazuh server nodes"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        try:
            stats = self.client.nodes.stats(metric="fs")
            nodes = stats.get("nodes", {})
            total_bytes = 0
            free_bytes = 0
            for node_id, node in nodes.items():
                fs = node.get("fs", {}).get("total", {})
                total_bytes += fs.get("total_in_bytes", 0)
                free_bytes += fs.get("available_in_bytes", 0)
            used_bytes = total_bytes - free_bytes
            pct = round((used_bytes / total_bytes * 100), 2) if total_bytes > 0 else 0

            def fmt(b):
                for unit in ["B", "KB", "MB", "GB", "TB"]:
                    if b < 1024:
                        return f"{b:.2f} {unit}"
                    b /= 1024
                return f"{b:.2f} PB"

            return {
                "total": fmt(total_bytes),
                "used": fmt(used_bytes),
                "free": fmt(free_bytes),
                "total_bytes": total_bytes,
                "used_bytes": used_bytes,
                "free_bytes": free_bytes,
                "percent": pct,
                "node_count": len(nodes),
            }
        except Exception as e:
            logger.error(f"Error getting node disk stats: {str(e)}")
            return {"error": str(e)}

    def export_indices_to_ndjson(self, index_names, output_file, progress_cb=None):
        """
        Export documents from a list of OpenSearch indices to a gzipped NDJSON file.
        Calls progress_cb(docs_written) periodically if provided.
        Returns total doc count.
        """
        import gzip
        import json as _json
        from opensearchpy import helpers as _helpers

        if not self.client:
            if not self._connect():
                raise RuntimeError("Failed to connect to OpenSearch")

        doc_count = 0
        with gzip.open(output_file, 'wt', encoding='utf-8') as f:
            for index_name in index_names:
                try:
                    for hit in _helpers.scan(
                        self.client,
                        index=index_name,
                        scroll='10m',
                        size=500,
                        preserve_order=False,
                    ):
                        f.write(_json.dumps(hit) + '\n')
                        doc_count += 1
                        if progress_cb and doc_count % 1000 == 0:
                            progress_cb(doc_count)
                except Exception as idx_err:
                    logger.error(f"export_indices_to_ndjson: error scanning {index_name}: {idx_err}")
        return doc_count

    def restore_ndjson_to_opensearch(self, backup_file, progress_cb=None):
        """
        Re-index all documents from a gzipped NDJSON backup file back to OpenSearch.
        Each document is restored to its original index (from the _index field in the hit).
        Returns (success_count, failed_count).
        """
        import gzip
        import json as _json
        from opensearchpy import helpers as _helpers

        if not self.client:
            if not self._connect():
                raise RuntimeError("Failed to connect to OpenSearch")

        processed = [0]

        def _actions():
            with gzip.open(backup_file, 'rt', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        hit = _json.loads(line)
                        processed[0] += 1
                        if progress_cb and processed[0] % 1000 == 0:
                            progress_cb(processed[0])
                        yield {
                            '_index': hit.get('_index', 'wazuh-restored'),
                            '_source': hit.get('_source', hit),
                        }
                    except Exception:
                        continue

        success, failed = _helpers.bulk(
            self.client, _actions(), raise_on_error=False, stats_only=True
        )
        return success, failed

    def get_index_stats(self):
        """Get statistics for the configured index pattern"""
        if not self.client:
            if not self._connect():
                return {"error": "Failed to connect to OpenSearch"}
        
        try:
            # Get matching indices
            indices = self.client.indices.get(index=self.index_pattern)
            
            # Get stats for all matching indices
            stats = self.client.indices.stats(index=self.index_pattern)
            
            return {
                "indices": list(indices.keys()),
                "stats": stats
            }
        except Exception as e:
            logger.error(f"Error getting index stats: {str(e)}")
            return {"error": str(e)}
