"""
Wazuh Integration Webhook with Prometheus Metrics
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import logging
from datetime import datetime
from crew import IPIntelligenceCrew
from utils.pdf_generator import generate_pdf_report

# ===== ADD PROMETHEUS METRICS =====
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI-SOC Wazuh Integration")

# ===== DEFINE METRICS =====
alerts_received_total = Counter(
    'wazuh_alerts_received_total',
    'Total alerts received from Wazuh',
    ['severity']
)

crewai_executions_total = Counter(
    'crewai_executions_total',
    'Total CrewAI agent executions',
    ['status']  # success, error, filtered
)

crewai_duration_seconds = Histogram(
    'crewai_execution_duration_seconds',
    'Time spent executing CrewAI analysis',
    buckets=[5, 10, 30, 60, 120, 300, 600]
)

alerts_filtered_total = Counter(
    'alerts_filtered_total',
    'Alerts filtered out (not sent to CrewAI)',
    ['reason']
)

active_investigations = Gauge(
    'crewai_active_investigations',
    'Number of active CrewAI investigations'
)


class WazuhAlert(BaseModel):
    alert_id: str | None = None
    timestamp: str | None = None
    rule_id: str | None = None
    rule_description: str | None = None
    rule_level: int | None = 0
    source_ip: str | None = ""
    dest_ip: str | None = ""
    source_port: int | None = 0
    dest_port: int | None = 0
    raw_log: str | None = ""


@app.post("/webhook")
async def receive_wazuh_alert(alert: WazuhAlert):
    """
    Receives Wazuh alerts → Triggers CrewAI → Tracks metrics
    """
    # Track alert received
    severity = "critical" if alert.rule_level >= 10 else "high" if alert.rule_level >= 8 else "medium"
    alerts_received_total.labels(severity=severity).inc()
    
    logger.info(f"Alert received: {alert.alert_id} - Level {alert.rule_level}")
    
    # Filter low-priority
    if alert.rule_level < 8:
        alerts_filtered_total.labels(reason="low_severity").inc()
        return {"status": "filtered", "reason": "severity_below_threshold"}
    
    # Filter missing IP
    if not alert.source_ip or alert.source_ip == "":
        alerts_filtered_total.labels(reason="no_source_ip").inc()
        return {"status": "filtered", "reason": "no_ip"}
    
    # Track active investigation
    active_investigations.inc()
    
    try:
        # Start timing
        start_time = time.time()
        
        logger.info(f"🔴 CRITICAL IP DETECTED - ACTIVATING CREWAI")
        logger.info(f"IP: {alert.source_ip}")
        
        # Execute CrewAI
        crew_instance = IPIntelligenceCrew()
        my_crew = crew_instance.crew()
        
        logger.info("⚡ CrewAI agents executing...")
        result = my_crew.kickoff(inputs={'ip_address': alert.source_ip})
        
        # Record success
        duration = time.time() - start_time
        crewai_duration_seconds.observe(duration)
        crewai_executions_total.labels(status="success").inc()
        
        logger.info(f"✅ CrewAI analysis complete in {duration:.2f}s")
        
        # Generate PDF
        pdf_path = generate_pdf_report(
            report_text=str(result),
            ip_address=alert.source_ip
        )
        
        return {
            "status": "success",
            "crewai_triggered": True,
            "pdf_report": pdf_path,
            "execution_time": f"{duration:.2f}s"
        }
        
    except Exception as e:
        logger.error(f"❌ CrewAI execution failed: {e}")
        crewai_executions_total.labels(status="error").inc()
        return {
            "status": "error",
            "error": str(e)
        }
    finally:
        # Decrement active count
        active_investigations.dec()


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "crewai-orchestrator"}


# ===== PROMETHEUS METRICS ENDPOINT =====
@app.get("/metrics")
async def metrics():
    """Expose Prometheus metrics"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)