import os
import requests
from crewai.tools import BaseTool


class AbuseIPDBTool(BaseTool):
    name: str = "AbuseIPDB Checker"
    description: str = "Check IP abuse reports and confidence scores from community-driven threat intelligence"
    
    def _run(self, ip_address: str) -> dict:
        """
        Check IP abuse reports in AbuseIPDB.
        
        Args:
            ip_address: IP address to check (e.g., '8.8.8.8')
        
        Returns:
            Dictionary with abuse confidence score, reports, and ISP info
        """
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        base_url = "https://api.abuseipdb.com/api/v2"
        
        try:
            response = requests.get(
                f"{base_url}/check",
                headers={'Accept': 'application/json', 'Key': api_key},
                params={'ipAddress': ip_address, 'maxAgeInDays': '90'},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                
                return {
                    "source": "AbuseIPDB",
                    "ip_address": ip_address,
                    "abuse_confidence_score": abuse_score,
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "verdict": "abusive" if abuse_score > 50 else "clean",
                    "summary": f"Abuse confidence: {abuse_score}% ({data.get('totalReports', 0)} reports)"
                }
            
            return {
                "source": "AbuseIPDB",
                "ip_address": ip_address,
                "error": f"Status {response.status_code}"
            }
        
        except Exception as e:
            return {
                "source": "AbuseIPDB",
                "ip_address": ip_address,
                "error": str(e)
            }