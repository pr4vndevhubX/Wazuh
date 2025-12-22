import requests
from crewai.tools import BaseTool


class YetiTool(BaseTool):
    name: str = "Yeti Threat Intelligence"
    description: str = "Search IP in internal Yeti threat intelligence database for historical context and tags"
    
    def _run(self, ip_address: str) -> dict:
        """
        Search IP in Yeti internal threat intelligence database.
        
        Args:
            ip_address: IP address to search (e.g., '8.8.8.8')
        
        Returns:
            Dictionary with Yeti findings, tags, and threat level
        """
        base_url = "http://192.168.217.128:8000"
        username = "admin"
        password = "XXXXXXXXXX"
        
        try:
            # Authenticate
            auth_response = requests.post(
                f"{base_url}/api/v2/auth/token",
                data={
                    "username": username,
                    "password": password,
                    "grant_type": "password"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            if auth_response.status_code != 200:
                return {
                    "source": "Yeti",
                    "ip_address": ip_address,
                    "error": "Auth failed"
                }
            
            token = auth_response.json()["access_token"]
            
            # Search observable
            search_response = requests.post(
                f"{base_url}/api/v2/observables/search",
                headers={"Authorization": f"Bearer {token}"},
                json={"query": {"value": ip_address}},
                timeout=15
            )
            
            if search_response.status_code == 200:
                data = search_response.json()
                observables = data.get("observables", [])
                
                if observables:
                    tags = [
                        tag.get("name")
                        for obs in observables
                        for tag in obs.get("tags", [])
                    ]
                    unique_tags = list(set(tags))
                    
                    verdict = "malicious" if any(
                        t in ["malware", "c2"] for t in unique_tags
                    ) else "suspicious"
                    
                    return {
                        "source": "Yeti",
                        "ip_address": ip_address,
                        "found": True,
                        "tags": unique_tags,
                        "verdict": verdict,
                        "summary": f"Found with tags: {', '.join(unique_tags[:3])}"
                    }
                
                return {
                    "source": "Yeti",
                    "ip_address": ip_address,
                    "found": False,
                    "message": "Not in Yeti"
                }
            
            return {
                "source": "Yeti",
                "ip_address": ip_address,
                "error": f"Status {search_response.status_code}"
            }
        
        except Exception as e:
            return {
                "source": "Yeti",
                "ip_address": ip_address,
                "error": str(e)
            }
