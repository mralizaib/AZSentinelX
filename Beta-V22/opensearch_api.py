import logging
import json
import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import ConnectionError, AuthenticationException, RequestError
from config import Config

logger = logging.getLogger(__name__)

class OpenSearchAPI:
    def __init__(self):
        self.host = Config.OPENSEARCH_URL
        self.username = Config.OPENSEARCH_USER
        self.password = Config.OPENSEARCH_PASSWORD
        self.verify_ssl = Config.OPENSEARCH_VERIFY_SSL
        self.index_pattern = Config.OPENSEARCH_INDEX_PATTERN
        self.client = None
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
                      additional_filters=None):
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
                        # Normalize common user-friendly terms to technical ones
                        normalized_value = value.lower()
                        if 'remote logon' in normalized_value or 'rdp' in normalized_value:
                            value = f"{value} \"Remote Logon\" OR \"RDP\" OR \"Terminal Services\""
                        
                        if 'malware' in normalized_value or 'persistence' in normalized_value:
                            value = f"{value} \"Malware\" OR \"Trojan\" OR \"Persistence\" OR \"Startup\" OR \"Service created\""

                        if 'privilege escalation' in normalized_value or 'sudo' in normalized_value:
                            value = f"{value} \"Privilege Escalation\" OR \"Elevated\" OR \"Admin\" OR \"Sudo\""

                        if 'network' in normalized_value or 'traffic' in normalized_value:
                            value = f"{value} \"Network\" OR \"Connection\" OR \"Port scan\" OR \"Inbound\" OR \"Outbound\""

                        if 'log integrity' in normalized_value or 'tampering' in normalized_value:
                            value = f"{value} \"Log cleared\" OR \"Audit log\" OR \"Tampering\" OR \"Event Log\""

                        if 'misconfiguration' in normalized_value or 'hardening' in normalized_value:
                            value = f"{value} \"Misconfiguration\" OR \"Hardening\" OR \"Policy\" OR \"Compliance\""
                        
                        # Multi-field search for agent name, IP, and description
                        # rule.description is a keyword field in Wazuh OpenSearch — wildcard
                        # queries are used to reliably match partial text against it.
                        wildcard_val = f"*{value.lower()}*"
                        query["bool"]["must"].append({
                            "bool": {
                                "should": [
                                    # ── Wildcard on keyword fields (primary match for rule.description) ──
                                    # rule.description is stored as keyword in Wazuh; multi_match exact
                                    # term matching won't find substrings. Wildcard with
                                    # case_insensitive guarantees partial matches.
                                    {
                                        "wildcard": {
                                            "rule.description": {
                                                "value": wildcard_val,
                                                "case_insensitive": True,
                                                "boost": 25
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "rule.groups": {
                                                "value": wildcard_val,
                                                "case_insensitive": True,
                                                "boost": 5
                                            }
                                        }
                                    },
                                    # ── Multi-match on text / analysed fields ──
                                    {
                                        "multi_match": {
                                            "query": value,
                                            "fields": [
                                                "agent.name^3",
                                                "agent.ip^3",
                                                "full_log^10",
                                                "data.win.eventdata.targetUserName^20",
                                                "data.win.eventdata.subjectUserName^20",
                                                "data.win.eventdata.logonId^5",
                                                "data.win.eventdata.logonType^5",
                                                "data.win.eventdata.ipAddress^10",
                                                "data.win.eventdata.ipPort^5",
                                                "data.win.eventdata.status^10",
                                                "data.win.eventdata.subStatus^10",
                                                "syscheck.uname_after^20",
                                                "syscheck.path^20",
                                                "data.win.eventdata.destinationUserName^20",
                                                "data.win.eventdata.sourceUserName^20",
                                                "data.win.eventdata.logonProcessName^10",
                                                "data.win.eventdata.authenticationPackageName^10",
                                                "data.win.eventdata.parentImage^15",
                                                "data.win.eventdata.commandLine^15",
                                                "data.win.eventdata.serviceName^15"
                                            ],
                                            "type": "best_fields",
                                            "fuzziness": "AUTO",
                                            "minimum_should_match": "1"
                                        }
                                    },
                                    # ── Exact phrase matches on specific keyword fields ──
                                    {
                                        "match_phrase": {
                                            "syscheck.path": {
                                                "query": value,
                                                "boost": 100
                                            }
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "data.win.eventdata.targetUserName": {
                                                "query": value,
                                                "boost": 100
                                            }
                                        }
                                    },
                                    # ── Wildcard on additional keyword fields ──
                                    {
                                        "wildcard": {
                                            "syscheck.path": {
                                                "value": wildcard_val,
                                                "case_insensitive": True,
                                                "boost": 80
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "data.win.eventdata.targetUserName": {
                                                "value": wildcard_val,
                                                "case_insensitive": True,
                                                "boost": 80
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "data.win.eventdata.commandLine": {
                                                "value": wildcard_val,
                                                "case_insensitive": True,
                                                "boost": 15
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "full_log": {
                                                "value": wildcard_val,
                                                "case_insensitive": True,
                                                "boost": 8
                                            }
                                        }
                                    }
                                ]
                            }
                        })
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
                results.append({
                    "id": hit["_id"],
                    "index": hit["_index"],
                    "score": hit["_score"],
                    "source": hit["_source"]
                })
            
            return {
                "total": total,
                "results": results,
                "request": search_body  # Include the request for debugging
            }
            
        except RequestError as e:
            logger.error(f"Error in search query: {str(e)}")
            return {"error": f"Query error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error searching alerts: {str(e)}")
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
                {
                    "term": {"rule.groups": "syscheck"}
                }
            ]

            # Agent name filter
            if agent_names:
                must_filters.append({
                    "terms": {"agent.name": agent_names}
                })

            # Path filter — match if syscheck.path starts with any configured path
            if paths:
                path_clauses = []
                for p in paths:
                    p_clean = p.rstrip('/')
                    path_clauses.append({"prefix": {"syscheck.path": p_clean}})
                    path_clauses.append({"term": {"syscheck.path": p_clean}})
                    path_clauses.append({
                        "wildcard": {
                            "syscheck.path": {
                                "value": f"{p_clean}*",
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
                    "source": hit["_source"]
                })

            return {"total": total, "results": results}

        except Exception as e:
            logger.error(f"Error searching FIM events: {str(e)}")
            return {"error": str(e)}

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
                                    {"terms": {"rule.id": [750, 60642, 752, 550, 60106]}},
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
