import os
import requests
import base64
from crewai.tools import BaseTool


class VirusTotalTool(BaseTool):
    name: str = "VirusTotal IP Checker"
    description: str = "Check IP reputation in VirusTotal database using 98+ security vendors"
    
    def _run(self, ip_address: str) -> dict:
        """
        Check IP reputation in VirusTotal database.
        
        Args:
            ip_address: IP address to check (e.g., '8.8.8.8')
        
        Returns:
            Dictionary with malicious count, reputation score, and verdict
        """
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        base_url = "https://www.virustotal.com/api/v3"
        
        try:
            url_id = base64.urlsafe_b64encode(
                f"http://{ip_address}/".encode()
            ).decode().strip("=")
            
            response = requests.get(
                f"{base_url}/urls/{url_id}",
                headers={"Accept": "application/json", "x-apikey": api_key},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                
                return {
                    "source": "VirusTotal",
                    "ip_address": ip_address,
                    "malicious_count": malicious,
                    "total_vendors": total,
                    "reputation": attributes.get("reputation", 0),
                    "verdict": "malicious" if malicious > 0 else "clean",
                    "summary": f"{malicious}/{total} vendors flagged as malicious"
                }
            
            return {
                "source": "VirusTotal",
                "ip_address": ip_address,
                "error": f"Status {response.status_code}"
            }
        
        except Exception as e:
            return {
                "source": "VirusTotal",
                "ip_address": ip_address,
                "error": str(e)
            }