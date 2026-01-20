"""
Alert Triage Tool
Connects crew to LLM-based alert triage service
"""

from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import requests
import logging

logger = logging.getLogger(__name__)


class AlertTriageInput(BaseModel):
    """Input for Alert Triage"""
    ip_address: str = Field(..., description="IP address from alert")
    alert_data: dict = Field(default={}, description="Wazuh alert details")


class AlertTriageTool(BaseTool):
    name: str = "Alert Triage Analyzer"
    description: str = (
        "Analyzes security alerts using LLM (Ollama). "
        "Determines severity, extracts IOCs, and provides recommendations. "
        "May be unavailable if Ollama is slow/offline."
    )
    args_schema: Type[BaseModel] = AlertTriageInput
    
    def _run(self, ip_address: str, alert_data: dict = None) -> dict:
        """
        Run LLM-based triage on alert.
        
        Args:
            ip_address: Source IP from alert
            alert_data: Full alert details from Wazuh
            
        Returns:
            dict: Triage analysis or fallback
        """
        try:
            # Build alert for triage service
            if alert_data is None:
                alert_data = {
                    "alert_id": f"ip-investigation-{ip_address}",
                    "source_ip": ip_address,
                    "rule_description": f"IP reputation investigation for {ip_address}",
                    "rule_level": 10
                }
            
            response = requests.post(
                "http://localhost:8100/analyze",
                json=alert_data,
                timeout=90  # Give Ollama time
            )
            
            if not response.ok:
                logger.warning(f"Alert triage service error: {response.status_code}")
                return self._fallback_analysis(ip_address)
            
            data = response.json()
            
            result = {
                "severity": data.get("severity", "medium"),
                "confidence": data.get("confidence", 0.5),
                "is_true_positive": data.get("is_true_positive", None),
                "iocs": data.get("iocs", []),
                "recommendations": data.get("recommendations", []),
                "mitre_techniques": data.get("mitre_techniques", []),
                "summary": data.get("summary", "No summary available"),
                "model_used": data.get("model_used", "unknown"),
                "ip_analyzed": ip_address,
                "service_status": "available"
            }
            
            logger.info(f"Alert triage for {ip_address}: {result['severity']} ({result['confidence']:.2f})")
            return result
            
        except requests.exceptions.Timeout:
            logger.warning(f"Alert triage timeout for {ip_address}")
            return self._fallback_analysis(ip_address, reason="LLM timeout (Ollama too slow)")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Alert triage connection error: {e}")
            return self._fallback_analysis(ip_address, reason="Service unavailable")
            
        except Exception as e:
            logger.error(f"Alert triage error: {e}")
            return self._fallback_analysis(ip_address, reason=str(e))
    
    def _fallback_analysis(self, ip_address: str, reason: str = "Service unavailable") -> dict:
        """Provide basic analysis when LLM service is down"""
        return {
            "severity": "medium",
            "confidence": 0.0,
            "is_true_positive": None,
            "iocs": [{"ioc_type": "ip", "value": ip_address}],
            "recommendations": [
                "Manual investigation required",
                "Check external reputation sources",
                "Review SIEM logs for activity"
            ],
            "mitre_techniques": [],
            "summary": f"LLM-based triage unavailable ({reason}). Defaulting to manual review.",
            "model_used": "fallback",
            "ip_analyzed": ip_address,
            "service_status": "unavailable",
            "fallback_reason": reason
        }