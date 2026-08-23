import logging
import os
import json
import requests
from datetime import datetime, timedelta
from sqlalchemy import text
from app import db
from models import RetentionPolicy
from opensearch_api import OpenSearchAPI
from config import Config

logger = logging.getLogger(__name__)

class RetentionManager:
    def __init__(self):
        self.opensearch = OpenSearchAPI()
    
    def _check_ism_available(self):
        """Check if OpenSearch Index State Management plugin is available"""
        try:
            self.opensearch.client.transport.perform_request('GET', '_plugins/_ism/policies')
            return True
        except Exception as e:
            logger.warning(f"ISM plugin not available: {str(e)}")
            return False
    
    def apply_retention_policy(self, policy_id=None):
        """
        Apply retention policy to clean up data
        
        Args:
            policy_id: Optional specific policy ID to apply, otherwise all enabled policies
            
        Returns:
            Dictionary with results summary
        """
        results = {
            'success': False,
            'policies_applied': 0,
            'errors': [],
            'details': []
        }
        
        try:
            # Get policies to apply
            if policy_id:
                policies = RetentionPolicy.query.filter_by(id=policy_id, enabled=True).all()
            else:
                policies = RetentionPolicy.query.filter_by(enabled=True).all()
            
            if not policies:
                results['errors'].append('No enabled retention policies found')
                return results
            
            # Apply each policy
            for policy in policies:
                result = self._apply_single_policy(policy)
                results['details'].append({
                    'policy_id': policy.id,
                    'policy_name': policy.name,
                    'status': 'success' if result['success'] else 'error',
                    'details': result
                })
                
                if result['success']:
                    # Update last run time
                    policy.last_run = datetime.utcnow()
                    db.session.commit()
                    results['policies_applied'] += 1
                else:
                    results['errors'].append(f"Policy {policy.name} (ID: {policy.id}): {result['error']}")
            
            results['success'] = len(results['errors']) == 0
            return results
            
        except Exception as e:
            logger.error(f"Error applying retention policies: {str(e)}")
            results['errors'].append(str(e))
            return results
    
    def _apply_single_policy(self, policy):
        """Apply a single retention policy"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None
        }
        
        try:
            if policy.source_type == 'opensearch':
                result = self._apply_opensearch_policy(policy)
            elif policy.source_type == 'wazuh':
                result = self._apply_wazuh_policy(policy)
            elif policy.source_type == 'database':
                result = self._apply_database_policy(policy)
            else:
                result['error'] = f"Unknown source type: {policy.source_type}"
                
            return result
        except Exception as e:
            logger.error(f"Error applying policy {policy.name}: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _apply_opensearch_policy(self, policy):
        """Apply retention policy to OpenSearch data"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None
        }
        
        try:
            # Calculate retention date
            retention_date = datetime.utcnow() - timedelta(days=policy.retention_days)
            retention_date_str = retention_date.isoformat()
            
            # Build the query
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "lt": retention_date_str
                        }
                    }
                }
            }
            
            # Add severity filters if specified
            severity_levels = policy.get_severity_levels()
            rule_ids = policy.get_rule_ids()
            
            if severity_levels or rule_ids:
                query["query"] = {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "lt": retention_date_str
                                    }
                                }
                            }
                        ]
                    }
                }
                
                if severity_levels:
                    # Map severity levels to rule.level ranges
                    level_ranges = []
                    for level in severity_levels:
                        if level == 'critical':
                            level_ranges.append({"term": {"rule.level": 15}})
                        elif level == 'high':
                            level_ranges.append({"range": {"rule.level": {"gte": 12, "lt": 15}}})
                        elif level == 'medium':
                            level_ranges.append({"range": {"rule.level": {"gte": 7, "lt": 12}}})
                        elif level == 'low':
                            level_ranges.append({"range": {"rule.level": {"gte": 1, "lt": 7}}})
                    
                    if level_ranges:
                        query["query"]["bool"]["must"].append({"bool": {"should": level_ranges}})
                
                if rule_ids:
                    rule_id_terms = [{"term": {"rule.id": rule_id}} for rule_id in rule_ids]
                    if rule_id_terms:
                        query["query"]["bool"]["must"].append({"bool": {"should": rule_id_terms}})
            
            # Execute deletion by query
            delete_response = self.opensearch.client.delete_by_query(
                index=self.opensearch.index_pattern,
                body=query,
                refresh=True
            )
            
            result['success'] = True
            result['items_deleted'] = delete_response['deleted']
            result['details'] = delete_response
            
            return result
        except Exception as e:
            logger.error(f"Error applying OpenSearch retention policy: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _apply_wazuh_policy(self, policy):
        """Apply retention policy to Wazuh data via OpenSearch ISM policies"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None
        }
        
        try:
            # Since Wazuh API doesn't support log retention, we'll use OpenSearch ISM policies
            # to manage the wazuh-alerts-* indices directly
            
            policy_id = f"wazuh-retention-policy-{policy.id}"
            
            # Create ISM policy for Wazuh alerts retention
            ism_policy = {
                "policy": {
                    "policy_id": policy_id,
                    "description": f"Wazuh alerts retention policy - {policy.name}",
                    "default_state": "retention_state",
                    "states": [
                        {
                            "name": "retention_state",
                            "actions": [],
                            "transitions": [
                                {
                                    "state_name": "delete_alerts",
                                    "conditions": {
                                        "min_index_age": f"{policy.retention_days}d"
                                    }
                                }
                            ]
                        },
                        {
                            "name": "delete_alerts",
                            "actions": [
                                {
                                    "retry": {
                                        "count": 3,
                                        "backoff": "exponential", 
                                        "delay": "1m"
                                    },
                                    "delete": {}
                                }
                            ],
                            "transitions": []
                        }
                    ],
                    "ism_template": [
                        {
                            "index_patterns": [
                                "wazuh-alerts-*"
                            ],
                            "priority": 1
                        }
                    ]
                }
            }
            
            # Apply the ISM policy via OpenSearch API
            try:
                # Create or update the ISM policy
                policy_url = f"_plugins/_ism/policies/{policy_id}"
                
                response = self.opensearch.client.transport.perform_request(
                    'PUT',
                    policy_url,
                    body=ism_policy
                )
                
                if response:
                    result['success'] = True
                    result['details'] = {
                        'message': f'OpenSearch ISM policy created for Wazuh retention ({policy.retention_days} days)',
                        'policy_id': policy_id,
                        'index_pattern': 'wazuh-alerts-*',
                        'retention_days': policy.retention_days
                    }
                    result['items_deleted'] = 1  # Policy created/updated
                    logger.info(f"Successfully created ISM policy {policy_id} for Wazuh retention")
                    return result
                else:
                    result['error'] = "Failed to create ISM policy"
                    return result
                    
            except Exception as ism_error:
                logger.error(f"ISM policy creation failed: {str(ism_error)}")
                
                # Fallback: Try direct deletion of old indices
                try:
                    cutoff_date = datetime.utcnow() - timedelta(days=policy.retention_days)
                    
                    # Get all wazuh-alerts indices
                    indices_response = self.opensearch.client.cat.indices(
                        index="wazuh-alerts-*",
                        format="json"
                    )
                    
                    deleted_indices = []
                    for index_info in indices_response:
                        index_name = index_info['index']
                        
                        # Extract date from index name (format: wazuh-alerts-4.x-YYYY.MM.DD)
                        try:
                            date_part = index_name.split('-')[-3:]  # Get last 3 parts: YYYY.MM.DD
                            if len(date_part) == 3:
                                index_date_str = '.'.join(date_part)
                                index_date = datetime.strptime(index_date_str, '%Y.%m.%d')
                                
                                if index_date < cutoff_date:
                                    # Delete the old index
                                    self.opensearch.client.indices.delete(index=index_name)
                                    deleted_indices.append(index_name)
                                    logger.info(f"Deleted old Wazuh index: {index_name}")
                        except (ValueError, IndexError) as date_error:
                            logger.warning(f"Could not parse date from index {index_name}: {date_error}")
                            continue
                    
                    if deleted_indices:
                        result['success'] = True
                        result['items_deleted'] = len(deleted_indices)
                        result['details'] = {
                            'message': f'Deleted {len(deleted_indices)} old Wazuh indices',
                            'deleted_indices': deleted_indices,
                            'retention_days': policy.retention_days,
                            'note': 'Direct index deletion used as fallback'
                        }
                    else:
                        result['success'] = True
                        result['items_deleted'] = 0
                        result['details'] = {
                            'message': 'No old Wazuh indices found to delete',
                            'retention_days': policy.retention_days
                        }
                    
                    return result
                    
                except Exception as delete_error:
                    result['error'] = f"Failed to create ISM policy and direct deletion failed: {str(delete_error)}"
                    return result
                
        except Exception as e:
            logger.error(f"Error applying Wazuh retention policy: {str(e)}")
            result['error'] = f"Error managing Wazuh retention: {str(e)}"
            return result
    
    def _apply_database_policy(self, policy):
        """Apply retention policy to database tables"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None,
            'tables': []
        }
        
        try:
            # Calculate retention date
            retention_date = datetime.utcnow() - timedelta(days=policy.retention_days)
            
            # Tables with created_at columns that can be pruned
            tables_to_clean = [
                'ai_insight_result',
                'alert_config',
                'report_config',
                'ai_insight_template'
            ]
            
            total_deleted = 0
            
            for table in tables_to_clean:
                try:
                    # Delete records older than retention date
                    sql = text(f"DELETE FROM {table} WHERE created_at < :retention_date")
                    delete_result = db.session.execute(sql, {'retention_date': retention_date})
                    deleted_count = delete_result.rowcount
                    
                    result['tables'].append({
                        'table': table,
                        'deleted': deleted_count
                    })
                    
                    total_deleted += deleted_count
                except Exception as table_error:
                    logger.error(f"Error cleaning table {table}: {str(table_error)}")
                    result['tables'].append({
                        'table': table,
                        'error': str(table_error)
                    })
            
            # Commit all changes
            db.session.commit()
            
            result['success'] = True
            result['items_deleted'] = total_deleted
            
            return result
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error applying database retention policy: {str(e)}")
            result['error'] = str(e)
            return result