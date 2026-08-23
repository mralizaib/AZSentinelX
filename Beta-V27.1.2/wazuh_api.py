import requests
import logging
import json
from flask import has_request_context, session
from config import Config
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Suppress insecure HTTPS request warnings if verify is set to False
if not Config.WAZUH_VERIFY_SSL:
    urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class WazuhAPI:
    def __init__(self, center=None):
        centers = Config.wazuh_centers()
        selected = center
        if selected is None and has_request_context():
            selected = session.get('wazuh_center', 'current')
        self.center_id = selected if selected in centers else 'current'
        center_config = centers[self.center_id]
        self.base_url = center_config['wazuh_api_url'].rstrip('/')
        self.username = center_config['wazuh_user']
        self.password = center_config['wazuh_password']
        self.verify_ssl = center_config['verify_ssl']
        self.token = None
        self.timeout = 15  # seconds

    def _get_token(self):
        """Get authentication token from Wazuh API"""
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                return True
            else:
                logger.error(f"Authentication failed. Status code: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error while authenticating with Wazuh API: {str(e)}")
            return False
    
    def _make_request(self, endpoint, method="GET", params=None, data=None):
        """Make a request to the Wazuh API"""
        if not self.token and not self._get_token():
            return {"error": "Authentication failed"}
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params, verify=self.verify_ssl, timeout=self.timeout)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, params=params, data=json.dumps(data), verify=self.verify_ssl, timeout=self.timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=headers, params=params, data=json.dumps(data), verify=self.verify_ssl, timeout=self.timeout)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, params=params, verify=self.verify_ssl, timeout=self.timeout)
            else:
                return {"error": f"Unsupported HTTP method: {method}"}
            
            # Handle 401 Unauthorized - Token may have expired
            if response.status_code == 401:
                if self._get_token():  # Try to get a new token
                    return self._make_request(endpoint, method, params, data)  # Retry the request
                else:
                    return {"error": "Unable to refresh authentication token"}

            # Wazuh sometimes returns an empty or non-JSON body (e.g. PUT
            # /agents/restart returns 200 with no content on some versions).
            # Wrap .json() in its own try-except so JSONDecodeError is handled
            # here rather than being swallowed by the outer except block.
            try:
                return response.json()
            except ValueError:
                # Empty or non-JSON body — treat 2xx as success
                if response.ok:
                    logger.debug(
                        f"Wazuh {method} {endpoint} returned non-JSON body "
                        f"(status {response.status_code}); treating as success."
                    )
                    return {
                        "data": {
                            "total_affected_items": 0,
                            "affected_items": [],
                            "failed_items": [],
                        },
                        "message": "OK",
                        "error": 0,
                    }
                return {"error": f"HTTP {response.status_code}: non-JSON response"}

        except Exception as e:
            logger.error(f"Error while making request to Wazuh API: {str(e)}")
            return {"error": str(e)}
    
    def get_agents(self, filters=None):
        """Get list of agents with optional filters"""
        params = filters or {}
        return self._make_request("/agents", params=params)
    
    def get_agent_details(self, agent_id):
        """Get details for a specific agent"""
        return self._make_request(f"/agents/{agent_id}")
    
    def get_rules(self, filters=None):
        """Get list of rules with optional filters"""
        params = filters or {}
        return self._make_request("/rules", params=params)
    
    def get_rule_details(self, rule_id):
        """Get details for a specific rule"""
        return self._make_request(f"/rules/{rule_id}")
    
    def get_alerts_summary(self):
        """Get summary of alerts"""
        return self._make_request("/overview/agents")
    
    def get_system_info(self):
        """Get Wazuh manager information"""
        return self._make_request("/manager/info")
    
    def get_manager_status(self):
        """Get Wazuh manager status"""
        return self._make_request("/manager/status")

    def get_sca_policies(self, agent_id, filters=None):
        """Get SCA policies for a specific agent"""
        params = filters or {}
        return self._make_request(f"/sca/{agent_id}", params=params)

    def get_sca_checks(self, agent_id, policy_id, filters=None):
        """Get SCA checks for a specific agent and policy"""
        params = filters or {}
        return self._make_request(f"/sca/{agent_id}/checks/{policy_id}", params=params)

    def get_agent_packages(self, agent_id, search=None, limit=100):
        """
        Query the Wazuh syscollector for installed packages on a specific agent.
        Returns a list of package dicts. Each dict may contain:
          name, version, architecture, location, vendor, install_time, format, source
        """
        params = {'limit': limit}
        if search:
            params['search'] = search
        result = self._make_request(f"/syscollector/{agent_id}/packages", params=params)
        return result.get('data', {}).get('affected_items', [])

    def restart_agents(self, agent_ids: list):
        """
        Send a restart command to a list of agents by their Wazuh agent ID.
        On restart, each agent automatically runs a fresh Syscollector scan.
        Agent IDs are batched (100 per request) to stay within API limits.
        Returns a list of raw API response dicts, one per batch.
        """
        if not agent_ids:
            return []
        BATCH = 100
        results = []
        for i in range(0, len(agent_ids), BATCH):
            batch = agent_ids[i:i + BATCH]
            resp = self._make_request(
                '/agents/restart',
                method='PUT',
                params={'agents_list': ','.join(str(aid) for aid in batch)},
            )
            results.append(resp)
            logger.info(
                f"Wazuh restart batch {i//BATCH + 1}: "
                f"{len(batch)} agents → "
                f"affected={resp.get('data',{}).get('total_affected_items','?')}"
            )
        return results

