"""
Wazuh Integration Webhook with Smart Routing & Prometheus Metrics
"""
from fastapi import FastAPI, HTTPException, Header
from typing import Optional
import httpx
import logging
from datetime import datetime
from crew import IPIntelligenceCrew
from utils.pdf_generator import generate_pdf_report

# ===== PROMETHEUS METRICS =====
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI-SOC Wazuh Integration")

# ===== SERVICE ENDPOINTS =====
ALERT_TRIAGE_URL = "http://localhost:8100/triage"
RAG_SERVICE_URL = "http://localhost:8001/query" 
ML_SERVICE_URL = "http://localhost:8500/predict" 

# ===== METRICS =====
alerts_received_total = Counter(
    'wazuh_alerts_received_total',
    'Total alerts received from Wazuh',
    ['severity']
)

crewai_executions_total = Counter(
    'crewai_executions_total',
    'Total CrewAI agent executions',
    ['status']
)

crewai_duration_seconds = Histogram(
    'crewai_execution_duration_seconds',
    'Time spent executing CrewAI analysis',
    buckets=[5, 10, 30, 60, 120, 300, 600]
)

alerts_filtered_total = Counter(
    'alerts_filtered_total',
    'Alerts filtered out',
    ['reason']
)

active_investigations = Gauge(
    'crewai_active_investigations',
    'Number of active CrewAI investigations'
)

triage_calls_total = Counter(
    'alert_triage_calls_total',
    'Total calls to alert triage service',
    ['status']
)

enrichment_calls_total = Counter(
    'enrichment_calls_total',
    'Total enrichment service calls',
    ['service', 'status']
)


@app.post("/webhook")
async def receive_wazuh_alert(
    alert: dict,
    x_api_key: Optional[str] = Header(None)
):
    """
    Smart Alert Router:
    - Level < 6: Archive only
    - Level 6-7: Dashboard only
    - Level 8-9: LLM triage + conditional enrichment
    - Level ≥ 10: Full triage + enrichment + flag for CrewAI
    """
    
    # Validate API key
    if x_api_key and x_api_key != "Apkl3@Jfyg2":
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Extract fields from Wazuh alert
    rule_level = alert.get("rule", {}).get("level", 0)
    rule_desc = alert.get("rule", {}).get("description", "")
    rule_id = alert.get("rule", {}).get("id", "")
    alert_id = alert.get("id", "")
    timestamp = alert.get("timestamp", datetime.now().isoformat())
    
    # Extract IPs
    source_ip = (
        alert.get("data", {}).get("srcip") or 
        alert.get("data", {}).get("src_ip") or
        alert.get("src_ip", "")
    )
    
    dest_ip = (
        alert.get("data", {}).get("dstip") or 
        alert.get("data", {}).get("dst_ip") or
        alert.get("dest_ip", "")
    )
    
    # Determine severity
    severity = (
        "critical" if rule_level >= 10 else
        "high" if rule_level >= 8 else
        "medium" if rule_level >= 6 else
        "low"
    )
    
    alerts_received_total.labels(severity=severity).inc()
    
    logger.info(f"📨 Alert: {rule_desc} | Level: {rule_level} | IP: {source_ip}")
    
    # ===== ROUTE 1: Level < 6 → Archive Only =====
    if rule_level < 6:
        alerts_filtered_total.labels(reason="low_severity").inc()
        logger.debug(f"Alert {alert_id} archived (level < 6)")
        return {
            "status": "archived",
            "reason": "level < 6",
            "action": "none"
        }
    
    # ===== ROUTE 2: Level 6-7 → Dashboard Only =====
    if rule_level < 8:
        alerts_filtered_total.labels(reason="dashboard_only").inc()
        logger.info(f"Alert {alert_id} stored to dashboard (level 6-7)")
        
        # Store to dashboard
        await store_to_dashboard({
            "alert_id": alert_id,
            "timestamp": timestamp,
            "rule_id": rule_id,
            "rule_description": rule_desc,
            "rule_level": rule_level,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "severity": severity,
            "raw_alert": alert
        })
        
        return {
            "status": "dashboard_stored",
            "reason": "level 6-7",
            "action": "metrics_only"
        }
    
    # ===== ROUTE 3 & 4: Level 8+ → LLM Triage + Conditional Enrichment =====
    
    logger.info(f"🟡 Level {rule_level}: Starting LLM triage")
    
    # Always run triage for level 8+
    triage_result = await call_alert_triage(alert)
    
    # Start building enriched alert
    enrichments = {
        "triage": triage_result
    }
    
    # Conditional enrichment based on triage severity
    triage_severity = triage_result.get("severity", "unknown")
    
    if triage_severity in ["high", "critical"]:
        logger.info(f"🔴 High/Critical alert - Running enrichments")
        
        # Run RAG for MITRE ATT&CK context
        enrichments["mitre"] = await call_rag_service(alert)
        
        # Run ML inference if source IP exists
        if source_ip:
            enrichments["ml"] = await call_ml_service(source_ip, alert)
        else:
            logger.warning("No source IP for ML inference")
    
    # Build final enriched alert
    final_alert = {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_description": rule_desc,
        "rule_level": rule_level,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "severity": severity,
        "enrichments": enrichments,
        "processed_at": datetime.now().isoformat(),
        "raw_alert": alert
    }
    
    # Store enriched alert to dashboard
    await store_to_dashboard(final_alert)
    
    # ===== Level 10+ → Flag for Potential CrewAI Investigation =====
    if rule_level >= 10:
        logger.warning(f"🔴 CRITICAL ALERT (Level {rule_level}) - Flagged for investigation")
        await flag_for_investigation(final_alert)
    
    return {
        "status": "processed",
        "alert_id": alert_id,
        "rule_level": rule_level,
        "triage_severity": triage_severity,
        "enrichments_applied": list(enrichments.keys()),
        "flagged_for_investigation": rule_level >= 10
    }


# ===== ANALYST-TRIGGERED CREWAI INVESTIGATION =====
@app.post("/investigate/{alert_id}")
async def trigger_crewai_investigation(alert_id: str):
    """
    Analyst triggers full CrewAI investigation for a specific alert
    This is called from the SOC dashboard when analyst clicks "Investigate"
    """
    
    logger.info(f"🚨 Analyst triggered CrewAI investigation for alert: {alert_id}")
    
    # Retrieve alert from dashboard/database
    alert_data = await get_alert_from_dashboard(alert_id)
    
    if not alert_data:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # CRITICAL DEBUG: Log what we retrieved
    logger.warning(f"🔍 RETRIEVED ALERT_DATA: {alert_data}")
    
    source_ip = alert_data.get("source_ip")
    logger.warning(f"🔍 EXTRACTED SOURCE_IP: {source_ip}")
    logger.warning(f"🔍 ALERT_DATA CONTENTS: {alert_data}")
    logger.warning(f"⚡ PASSING TO CREWAI: ip_address={source_ip}")
    
    if not source_ip:
        raise HTTPException(status_code=400, detail="No source IP in alert")
    
    active_investigations.inc()
    
    try:
        start_time = time.time()
        
        logger.warning(f"⚡ PASSING TO CREWAI: ip_address={source_ip}")
        
        # Execute full CrewAI investigation
        crew_instance = IPIntelligenceCrew()
        my_crew = crew_instance.crew()
        
        # CRITICAL: Pass the IP to CrewAI
        result = my_crew.kickoff(inputs={'ip_address': source_ip})
        
        duration = time.time() - start_time
        crewai_duration_seconds.observe(duration)
        crewai_executions_total.labels(status="success").inc()
        
        logger.info(f"✅ CrewAI analysis complete in {duration:.2f}s")
        
        # Generate PDF report
        pdf_path = generate_pdf_report(
            report_text=str(result),
            ip_address=source_ip
        )
        
        # Update alert with investigation results
        await update_alert_investigation(alert_id, {
            "investigation_completed": True,
            "investigation_result": str(result),
            "pdf_report": pdf_path,
            "execution_time": duration
        })
        
        return {
            "status": "success",
            "alert_id": alert_id,
            "ip_address": source_ip,
            "pdf_report": pdf_path,
            "execution_time": f"{duration:.2f}s",
            "raw_result": str(result)
        }
        
    except Exception as e:
        logger.error(f"❌ CrewAI execution failed: {e}")
        crewai_executions_total.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        active_investigations.dec()


# ===== SERVICE CALLERS =====

async def call_alert_triage(alert: dict) -> dict:
    """Call LLM triage service (port 8100)"""
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                ALERT_TRIAGE_URL,
                json=alert,
                timeout=10.0
            )
            
            triage_calls_total.labels(status="success").inc()
            
            result = response.json()
            logger.info(f"Triage result: {result.get('severity')} (confidence: {result.get('confidence')})")
            
            return result
            
        except httpx.TimeoutException:
            logger.error("Triage service timeout")
            triage_calls_total.labels(status="timeout").inc()
            return {"severity": "unknown", "error": "timeout", "confidence": 0}
            
        except Exception as e:
            logger.error(f"Triage service error: {e}")
            triage_calls_total.labels(status="error").inc()
            return {"severity": "unknown", "error": str(e), "confidence": 0}


async def call_rag_service(alert: dict) -> dict:
    """Get MITRE ATT&CK context from RAG service (port 8200)"""
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                RAG_SERVICE_URL,
                json={
                    "query": alert.get("rule", {}).get("description", ""),
                    "rule_id": alert.get("rule", {}).get("id", "")
                },
                timeout=15.0
            )
            
            enrichment_calls_total.labels(service="rag", status="success").inc()
            
            result = response.json()
            logger.info(f"RAG found {len(result.get('techniques', []))} MITRE techniques")
            
            return result
            
        except Exception as e:
            logger.error(f"RAG service error: {e}")
            enrichment_calls_total.labels(service="rag", status="error").inc()
            return {"techniques": [], "error": str(e)}


async def call_ml_service(ip: str, alert: dict) -> dict:
    """Get ML prediction for IP (port 8300)"""
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                ML_SERVICE_URL,
                json={
                    "ip_address": ip,
                    "alert_data": alert
                },
                timeout=5.0
            )
            
            enrichment_calls_total.labels(service="ml", status="success").inc()
            
            result = response.json()
            logger.info(f"ML prediction: {result.get('prediction')} (confidence: {result.get('confidence')})")
            
            return result
            
        except Exception as e:
            logger.error(f"ML service error: {e}")
            enrichment_calls_total.labels(service="ml", status="error").inc()
            return {"prediction": "unknown", "confidence": 0, "error": str(e)}


# ===== DATABASE/STORAGE HELPERS =====
alert_store = {}

async def store_to_dashboard(alert: dict):
    """Store alert to memory"""
    alert_id = alert.get('alert_id')
    if alert_id:
        alert_store[alert_id] = alert
        logger.warning(f"📊 STORED ALERT: {alert_id} with source_ip={alert.get('source_ip')}")
    # Example: await db.alerts.insert_one(alert)


async def flag_for_investigation(alert: dict):
    """
    Flag critical alerts for analyst review
    TODO: Implement investigation queue
    """
    logger.warning(f"🚩 Alert {alert.get('alert_id')} flagged for investigation")
    # Example: await db.investigation_queue.insert_one(alert)


async def get_alert_from_dashboard(alert_id: str) -> dict:
    """Retrieve alert from memory"""
    logger.info(f"📖 Retrieving alert {alert_id} from dashboard")
    
    alert = alert_store.get(alert_id)
    
    if not alert:
        logger.error(f"❌ Alert {alert_id} not found in store. Available: {list(alert_store.keys())}")
        return None
    
    logger.warning(f"✅ Found alert {alert_id} with keys: {list(alert.keys())}")
    return alert


async def update_alert_investigation(alert_id: str, investigation_data: dict):
    """
    Update alert with investigation results
    TODO: Implement actual update
    """
    logger.info(f"📝 Updated alert {alert_id} with investigation results")


# ===== HEALTH & METRICS =====

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "wazuh-integration",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/metrics")
async def metrics():
    """Expose Prometheus metrics"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)