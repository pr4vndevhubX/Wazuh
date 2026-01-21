"""
Alert Triage Service - LLM-based Security Alert Analysis
Runs on port 8000 (exposed as 8100 via Docker)
Uses Ollama with llama3.2:3b for alert severity analysis
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
import requests
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Alert Triage Service",
    description="LLM-powered security alert analysis using Ollama",
    version="1.0.0"
)

# Ollama configuration
OLLAMA_URL = "http://ollama:11434"  # Docker network name
OLLAMA_MODEL = "llama3.2:3b"


class AlertData(BaseModel):
    """Wazuh alert structure"""
    alert_id: str = Field(..., description="Unique alert identifier")
    source_ip: str = Field(..., description="Source IP address")
    rule_description: str = Field(..., description="Alert rule description")
    rule_level: int = Field(..., description="Alert severity level (0-15)")
    rule_id: Optional[str] = Field(None, description="Wazuh rule ID")
    timestamp: Optional[str] = Field(None, description="Alert timestamp")
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    full_log: Optional[str] = None


class TriageResponse(BaseModel):
    """LLM triage analysis result"""
    severity: str = Field(..., description="low, medium, high, critical")
    confidence: float = Field(..., description="Confidence score 0.0-1.0")
    is_true_positive: Optional[bool] = Field(None, description="True positive assessment")
    iocs: List[dict] = Field(default_factory=list, description="Indicators of Compromise")
    recommendations: List[str] = Field(default_factory=list, description="Action items")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK mappings")
    summary: str = Field(..., description="Brief analysis summary")
    model_used: str = Field(..., description="LLM model used")
    processing_time_ms: float = Field(..., description="Analysis duration")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check Ollama connectivity
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        ollama_status = "healthy" if response.ok else "unhealthy"
    except Exception as e:
        ollama_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "ollama_status": ollama_status,
        "model": OLLAMA_MODEL
    }


@app.post("/analyze", response_model=TriageResponse)
async def analyze_alert(alert: AlertData):
    """
    Main endpoint: Analyze security alert using LLM
    
    Args:
        alert: Wazuh alert data
        
    Returns:
        TriageResponse: LLM-based analysis
    """
    start_time = datetime.now()
    
    try:
        # Build LLM prompt
        prompt = build_analysis_prompt(alert)
        
        # Call Ollama
        llm_response = call_ollama(prompt)
        
        # Parse LLM output
        result = parse_llm_response(llm_response, alert)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        result["processing_time_ms"] = processing_time
        result["model_used"] = OLLAMA_MODEL
        
        logger.info(f"Analyzed alert {alert.alert_id}: {result['severity']} ({result['confidence']:.2f})")
        
        return result
        
    except Exception as e:
        logger.error(f"Analysis error for {alert.alert_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/triage", response_model=TriageResponse)
async def triage_alert(alert: AlertData):
    """Alias endpoint for /analyze (backwards compatibility)"""
    return await analyze_alert(alert)


def build_analysis_prompt(alert: AlertData) -> str:
    """
    Construct detailed LLM prompt for alert analysis
    
    Args:
        alert: Alert data
        
    Returns:
        str: Formatted prompt
    """
    prompt = f"""You are a cybersecurity analyst performing triage on a security alert. Analyze the following alert and provide a structured assessment.

**ALERT DETAILS:**
- Alert ID: {alert.alert_id}
- Source IP: {alert.source_ip}
- Rule: {alert.rule_description}
- Wazuh Severity Level: {alert.rule_level} (scale 0-15)
"""

    if alert.destination_ip:
        prompt += f"- Destination IP: {alert.destination_ip}\n"
    if alert.destination_port:
        prompt += f"- Destination Port: {alert.destination_port}\n"
    if alert.protocol:
        prompt += f"- Protocol: {alert.protocol}\n"
    if alert.full_log:
        prompt += f"- Raw Log:\n{alert.full_log[:500]}\n"

    prompt += """
**YOUR TASK:**
Provide a structured analysis in the following JSON format (respond ONLY with valid JSON, no markdown):

{
  "severity": "low|medium|high|critical",
  "confidence": 0.0-1.0,
  "is_true_positive": true|false|null,
  "iocs": [
    {"ioc_type": "ip|domain|hash|url", "value": "..."},
    ...
  ],
  "recommendations": [
    "Specific action item 1",
    "Specific action item 2",
    ...
  ],
  "mitre_techniques": ["T1190", "T1110", ...],
  "summary": "Brief 2-3 sentence analysis"
}

**GUIDELINES:**
- Severity: Map Wazuh level to realistic threat (0-5=low, 6-9=medium, 10-12=high, 13-15=critical)
- Confidence: How certain are you? (0.0=guess, 1.0=certain)
- True Positive: Is this a real attack or likely false positive?
- IOCs: Extract IP addresses, domains, file hashes, URLs from the alert
- Recommendations: Concrete next steps (block IP, investigate user, patch system, etc.)
- MITRE: Map to ATT&CK techniques if applicable (e.g., T1190 for exploit, T1110 for brute force)
- Summary: Explain what happened and why it matters

Respond now with ONLY the JSON object:"""

    return prompt


def call_ollama(prompt: str, max_retries: int = 2) -> str:
    """
    Call Ollama API for LLM inference
    
    Args:
        prompt: Analysis prompt
        max_retries: Number of retry attempts
        
    Returns:
        str: LLM response text
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,  # Lower temp for more consistent JSON
            "top_p": 0.9,
            "num_predict": 1024
        }
    }
    
    for attempt in range(max_retries):
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json=payload,
                timeout=90  # LLM inference can be slow
            )
            
            if not response.ok:
                logger.warning(f"Ollama error (attempt {attempt+1}): {response.status_code}")
                continue
            
            data = response.json()
            return data.get("response", "")
            
        except requests.exceptions.Timeout:
            logger.warning(f"Ollama timeout (attempt {attempt+1})")
            if attempt == max_retries - 1:
                raise
        except Exception as e:
            logger.error(f"Ollama call failed: {e}")
            if attempt == max_retries - 1:
                raise
    
    raise Exception("Ollama API unavailable after retries")


def parse_llm_response(llm_text: str, alert: AlertData) -> dict:
    """
    Parse LLM JSON response with fallback logic
    
    Args:
        llm_text: Raw LLM output
        alert: Original alert data
        
    Returns:
        dict: Parsed triage result
    """
    import json
    import re
    
    try:
        # Try to extract JSON from response (handle markdown wrapping)
        json_match = re.search(r'\{.*\}', llm_text, re.DOTALL)
        if json_match:
            llm_data = json.loads(json_match.group(0))
        else:
            llm_data = json.loads(llm_text)
        
        # Validate required fields
        result = {
            "severity": llm_data.get("severity", "medium").lower(),
            "confidence": float(llm_data.get("confidence", 0.7)),
            "is_true_positive": llm_data.get("is_true_positive"),
            "iocs": llm_data.get("iocs", []),
            "recommendations": llm_data.get("recommendations", []),
            "mitre_techniques": llm_data.get("mitre_techniques", []),
            "summary": llm_data.get("summary", "LLM analysis completed")
        }
        
        # Ensure severity is valid
        if result["severity"] not in ["low", "medium", "high", "critical"]:
            result["severity"] = map_wazuh_level_to_severity(alert.rule_level)
        
        # Ensure confidence is in range
        result["confidence"] = max(0.0, min(1.0, result["confidence"]))
        
        # Add source IP as IOC if not present
        if not any(ioc.get("value") == alert.source_ip for ioc in result["iocs"]):
            result["iocs"].insert(0, {"ioc_type": "ip", "value": alert.source_ip})
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to parse LLM response: {e}")
        logger.debug(f"LLM output: {llm_text}")
        
        # Fallback to rule-based analysis
        return {
            "severity": map_wazuh_level_to_severity(alert.rule_level),
            "confidence": 0.5,
            "is_true_positive": None,
            "iocs": [{"ioc_type": "ip", "value": alert.source_ip}],
            "recommendations": [
                "Manual review required - LLM parsing failed",
                "Check external threat intelligence",
                "Review SIEM logs for correlated activity"
            ],
            "mitre_techniques": [],
            "summary": f"Automated analysis unavailable. Alert: {alert.rule_description}"
        }


def map_wazuh_level_to_severity(level: int) -> str:
    """Map Wazuh severity level (0-15) to category"""
    if level <= 5:
        return "low"
    elif level <= 9:
        return "medium"
    elif level <= 12:
        return "high"
    else:
        return "critical"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")