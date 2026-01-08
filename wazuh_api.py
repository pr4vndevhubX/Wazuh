from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn
import sys
import os
import traceback

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.alert_storage import AlertStorage

app = FastAPI(title="Wazuh Alert Receiver")
alert_storage = AlertStorage()

stats = {'total_received': 0, 'stored': 0, 'filtered': 0}

API_KEY = "Apkl3@Jfyg2"

@app.post("/loghook")
async def loghook(request: Request):
    try:
        # 1️⃣ Authenticate Wazuh
        if request.headers.get("X-API-Key") != API_KEY:
            print("❌ Unauthorized request")
            return JSONResponse(
                status_code=401,
                content={"status": "unauthorized"}
            )

        payload = await request.json()

        # =========================
        # 🔁 HANDLE BATCH ALERTS
        # =========================
        if isinstance(payload, list):
            stored_count = 0

            for alert in payload:
                try:
                    # Safe extraction of rule level
                    rule_level = alert.get("rule", {}).get("level", 0)
                    
                    # Handle None or non-numeric values
                    if rule_level is None:
                        rule_level = 0
                    else:
                        rule_level = int(rule_level)

                    if rule_level < 5:
                        stats['filtered'] += 1
                        continue

                    alert_storage.store_alert(alert)
                    stored_count += 1
                    
                except Exception as alert_error:
                    print(f"⚠️ Error processing individual alert: {alert_error}")
                    print(f"Alert data: {alert}")
                    continue

            stats['total_received'] += len(payload)
            stats['stored'] += stored_count

            print(f"📦 Batch received | Total: {len(payload)} | Stored: {stored_count}")

            return {
                "status": "stored",
                "batch_size": len(payload),
                "stored": stored_count
            }

        # =========================
        # 🔔 HANDLE SINGLE ALERT
        # =========================
        alert = payload.get("alert", payload)
        
        # Safe extraction of rule level
        rule_level = alert.get("rule", {}).get("level", 0)
        
        # Handle None or non-numeric values
        if rule_level is None:
            rule_level = 0
        else:
            rule_level = int(rule_level)

        print(f"📩 Received alert | Level: {rule_level}")

        stats['total_received'] += 1

        if rule_level < 5:
            stats['filtered'] += 1
            return {"status": "filtered"}

        alert_id = alert_storage.store_alert(alert)
        stats['stored'] += 1

        print(f"✅ Stored alert ID: {alert_id}")

        return {
            "status": "stored",
            "alert_id": alert_id,
            "level": rule_level
        }

    except Exception as e:
        # Enhanced error logging
        error_msg = str(e) if str(e) else repr(e)
        error_trace = traceback.format_exc()
        
        print(f"❌ Error: {error_msg}")
        print(f"📋 Full traceback:\n{error_trace}")
        
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error": error_msg,
                "type": type(e).__name__
            }
        )
    
@app.get("/stats")
async def get_stats():
    return {
        "webhook_stats": stats,
        "database_stats": alert_storage.get_stats()
    }

@app.get("/alerts/recent")
async def get_recent_alerts(limit: int = 10):
    alerts = alert_storage.get_unprocessed_alerts(limit)
    return {"count": len(alerts), "alerts": alerts}

if __name__ == "__main__":
    print("🚀 Starting Wazuh Alert Receiver")
    uvicorn.run(app, host="0.0.0.0", port=3030)