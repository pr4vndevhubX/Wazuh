"""
Alert Triage Tool - CrewAI wrapper for Alert Triage Service
Calls the FastAPI service at localhost:8100
"""

from crewai.tools import BaseTool
from typing import Type, Optional
from pydantic import BaseModel, Field
import requests
import logging

logger = logging.getLogger(__name__)

class AlertTriageInput(BaseModel):
    """Input schema for alert triage tool"""
    alert_id: str = Field(..., description="Unique alert identifier")
    source_ip: str = Field(..., description="Source IP address")
    rule_description: str = Field(..., description="Alert rule description")
    rule_level: int = Field(..., description="Alert severity level (0-15)")
    rule_id: Optional[str] = Field(None, description="Wazuh rule ID")
    timestamp: Optional[str] = Field(None, description="Alert timestamp")

class AlertTriageTool(BaseTool):
    name: str = "Alert Triage Analysis"
    description: str = (
        "Analyzes security alerts using LLM-based triage service. "
        "Provides severity assessment, confidence score, IOCs, and recommendations. "
        "Input: alert_id, source_ip, rule_description, rule_level"
    )
    args_schema: Type[BaseModel] = AlertTriageInput
    
    def _run(
        self,
        alert_id: str,
        source_ip: str,
        rule_description: str,
        rule_level: int,
        rule_id: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> dict:
        """
        Call Alert Triage Service to analyze alert
        
        Args:
            alert_id: Unique identifier
            source_ip: Source IP address
            rule_description: Alert description
            rule_level: Severity level (0-15)
            rule_id: Optional rule ID
            timestamp: Optional timestamp
            
        Returns:
            dict: Triage analysis result
        """
        try:
            payload = {
                "alert_id": alert_id,
                "source_ip": source_ip,
                "rule_description": rule_description,
                "rule_level": rule_level
            }
            
            if rule_id:
                payload["rule_id"] = rule_id
            if timestamp:
                payload["timestamp"] = timestamp
            
            response = requests.post(
                "http://localhost:8100/triage",
                json=payload,
                timeout=15.0
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Triage completed: {result.get('severity')} ({result.get('confidence')})")
                return result
            else:
                logger.error(f"Triage service error: {response.status_code}")
                return {
                    "error": f"Service returned {response.status_code}",
                    "severity": "unknown",
                    "confidence": 0.0
                }
                
        except requests.exceptions.ConnectionError:
            logger.warning("Alert Triage Service unavailable")
            return {
                "error": "Service unavailable",
                "severity": "unknown",
                "confidence": 0.0,
                "summary": "Alert Triage Service is not running"
            }
        except Exception as e:
            logger.error(f"Alert triage error: {e}")
            return {
                "error": str(e),
                "severity": "unknown",
                "confidence": 0.0
            }