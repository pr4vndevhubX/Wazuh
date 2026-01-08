from crewai.tools import BaseTool
import requests

class AlertTriageTool(BaseTool):
    name: str = "Alert Triage Analyzer"
    description: str = "Analyzes security alerts using LLM (may be unavailable)"
    
    def _run(self, alert_data: dict) -> str:
        try:
            response = requests.post(
                "http://localhost:8100/analyze",
                json=alert_data,
                timeout=30
            )
            return response.json() if response.ok else "Service unavailable"
        except:
            return "Alert Triage service not available - skipping LLM analysis"