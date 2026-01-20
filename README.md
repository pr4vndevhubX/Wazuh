run code : "python -m streamlit run app.py"

# CrewAI IP Intelligence → AI-SOC Integration Plan

## Current State
```
┌─────────────────────────────────────────────────────────┐
│  YOUR CREWAI SYSTEM (Standalone)                        │
│  Port: 8501                                             │
│  - 7 AI Agents (Coordinator, VT, AbuseIPDB, Yeti, etc.) │
│  - Tools: VirusTotal, AbuseIPDB, Yeti, Wazuh SIEM      │
│  - Output: PDF Reports                                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  EXISTING AI-SOC INFRASTRUCTURE (Separate)              │
│  - ML Inference (:8500) - Network traffic classification│
│  - Alert Triage (:8100) - LLM alert analysis            │
│  - RAG Service (:8300) - MITRE ATT&CK knowledge base    │
└─────────────────────────────────────────────────────────┘
```

## Target Architecture (Integrated)
```
┌──────────────────────────────────────────────────────────────────────┐
│                    USER INTERFACES                                    │
├──────────────────────────────────────────────────────────────────────┤
│  Wazuh (:443) │ Unified Dashboard (:3000) │ Grafana (:3001)          │
│                      ↓                                                │
│               [Shows both ML alerts                                   │
│                + IP Intelligence Reports]                             │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATION LAYER (NEW)                          │
├──────────────────────────────────────────────────────────────────────┤
│  Threat Intelligence Orchestrator (:8600)                             │
│  - Receives alerts from Alert Triage                                  │
│  - Extracts suspicious IPs from alerts                                │
│  - Triggers CrewAI IP analysis                                        │
│  - Enriches alerts with IP intelligence                               │
│  - Sends enriched data to Dashboard                                   │
└──────────────────────────────────────────────────────────────────────┘
         ↓                    ↓                    ↓
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│ ML Inference   │  │ Alert Triage   │  │ RAG Service    │
│ :8500          │  │ :8100          │  │ :8300          │
│ Network Traffic│  │ LLM Analysis   │  │ MITRE ATT&CK   │
└────────────────┘  └────────────────┘  └────────────────┘
                           ↓
                  ┌────────────────┐
                  │ CrewAI System  │
                  │ :8501          │
                  │ IP Intelligence│
                  └────────────────┘
```

## Integration Points

### 1. **CrewAI API Wrapper** (NEW - Step 1)
**Purpose:** Expose your CrewAI crew as a REST API instead of standalone script

**File:** `services/crewai-intelligence/api_server.py`

**Endpoints:**
- `POST /analyze-ip` - Analyze single or multiple IPs
- `GET /health` - Service health check
- `GET /status/{task_id}` - Check analysis status

**Changes to CrewAI:**
- Keep all 7 agents unchanged
- Keep all tools (VT, AbuseIPDB, Yeti, Wazuh) unchanged
- Wrap `IPIntelligenceCrew.crew().kickoff()` in FastAPI endpoint
- Return JSON instead of PDF (PDF as optional download)

---

### 2. **Orchestration Service** (NEW - Step 2)
**Purpose:** Bridge between Alert Triage and CrewAI

**File:** `services/threat-orchestrator/main.py`

**Workflow:**
```python
1. Listen for alerts from Alert Triage (:8100)
2. Extract IPs from alert (source_ip, destination_ip)
3. Check cache: Have we analyzed this IP recently?
4. If not cached → Call CrewAI API (:8501)
5. Get RAG context from :8300 for MITRE techniques
6. Merge: Alert data + IP intelligence + MITRE context
7. Store in database (PostgreSQL)
8. Send to Dashboard via WebSocket
```

**Database Schema:**
```sql
CREATE TABLE enriched_alerts (
  id SERIAL PRIMARY KEY,
  alert_id VARCHAR(100),
  timestamp TIMESTAMP,
  ml_verdict VARCHAR(20),           -- From ML Inference
  ml_confidence FLOAT,               -- From ML Inference
  alert_summary TEXT,                -- From Alert Triage
  suspicious_ip VARCHAR(45),         -- Extracted IP
  ip_threat_level VARCHAR(20),       -- CRITICAL/HIGH/etc from CrewAI
  ip_vt_score VARCHAR(10),           -- 5/98 from CrewAI
  ip_abuseipdb_score INT,            -- 0-100 from CrewAI
  ip_yeti_status VARCHAR(20),        -- Found/Not Found from CrewAI
  mitre_techniques TEXT[],           -- From RAG
  full_report JSONB                  -- Complete CrewAI output
);
```

---

### 3. **Dashboard Enhancement** (NEW - Step 3)
**Purpose:** Display unified view of ML alerts + IP intelligence

**File:** `services/web-dashboard/src/components/EnrichedAlertView.jsx`

**UI Layout:**
```
┌─────────────────────────────────────────────────────────┐
│  Alert #1733110600.FINAL                     🔴 CRITICAL│
├─────────────────────────────────────────────────────────┤
│  📊 ML Classification                                    │
│  Verdict: MALICIOUS (86% confidence)                    │
│  Flow: 192.168.1.100 → 185.196.10.10:22                │
│                                                          │
│  🔍 IP Intelligence (185.196.10.10)                     │
│  VirusTotal: 5/98 vendors flagged                       │
│  AbuseIPDB: 0% confidence                               │
│  Yeti: Found (tags: malware, c2, blocklist)             │
│  Verdict: 💀 CRITICAL - Known C2 server                │
│                                                          │
│  🎯 MITRE ATT&CK                                        │
│  T1071.001 - Web Protocols (C2)                         │
│  T1090 - Proxy                                          │
│                                                          │
│  [View Full Report] [Block IP] [Create Ticket]          │
└─────────────────────────────────────────────────────────┘
```

---

### 4. **RAG Service Integration** (MODIFY - Step 4)
**Purpose:** Let CrewAI agents query MITRE ATT&CK knowledge base

**File:** `services/crewai-intelligence/tools/rag_tool.py` (NEW)

**Integration:**
```python
# CrewAI agent can now call RAG service
from crewai import Tool

rag_tool = Tool(
    name="MITRE ATT&CK Knowledge Base",
    description="Query MITRE ATT&CK techniques related to IP threat behavior",
    func=lambda query: requests.post(
        "http://localhost:8300/retrieve",
        json={"query": query, "top_k": 5}
    ).json()
)

# Add to analyst_agent
analyst_agent.tools = [rag_tool]
```

---

## Implementation Steps

### Phase 1: Basic Integration (Week 1)
✅ **Step 1.1:** Convert CrewAI to FastAPI service  
✅ **Step 1.2:** Create Orchestrator service skeleton  
✅ **Step 1.3:** Test: Alert Triage → Orchestrator → CrewAI  

### Phase 2: Data Flow (Week 2)
✅ **Step 2.1:** Add PostgreSQL database for enriched alerts  
✅ **Step 2.2:** Implement IP caching (Redis)  
✅ **Step 2.3:** Connect Orchestrator to RAG service  

### Phase 3: Dashboard (Week 3)
✅ **Step 3.1:** Create EnrichedAlertView component  
✅ **Step 3.2:** Add WebSocket for real-time updates  
✅ **Step 3.3:** Implement "View Full Report" modal  

### Phase 4: Advanced Features (Week 4)
✅ **Step 4.1:** Add RAG tool to CrewAI agents  
✅ **Step 4.2:** Implement auto-blocking workflow  
✅ **Step 4.3:** Add Grafana dashboard for metrics  

---

## Docker Compose Changes

### New Services to Add:
```yaml
# docker-compose/ai-services.yml (ADD THESE)

  crewai-intelligence:
    build: ../services/crewai-intelligence
    ports:
      - "8501:8501"
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - YETI_URL=${YETI_URL}
      - WAZUH_API_URL=https://wazuh-manager:55000
    depends_on:
      - ollama
      - redis
    networks:
      - ai-backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8501/health"]
      interval: 30s

  threat-orchestrator:
    build: ../services/threat-orchestrator
    ports:
      - "8600:8600"
    environment:
      - ALERT_TRIAGE_URL=http://alert-triage:8100
      - CREWAI_URL=http://crewai-intelligence:8501
      - RAG_URL=http://rag-service:8300
      - POSTGRES_URL=postgresql://user:pass@postgres:5432/aisoc
      - REDIS_URL=redis://redis:6379
    depends_on:
      - alert-triage
      - crewai-intelligence
      - rag-service
      - postgres
      - redis
    networks:
      - ai-backend
      - monitoring
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8600/health"]
      interval: 30s
```

---

## Configuration Files Needed

1. `services/crewai-intelligence/.env`
2. `services/threat-orchestrator/.env`
3. `services/threat-orchestrator/config.yaml`
4. `docker-compose/ai-services-integrated.yml`

---

## Success Criteria

### ✅ Integration Complete When:
1. Alert Triage sends alert → Orchestrator extracts IP → CrewAI analyzes
2. Dashboard shows unified view: ML verdict + IP intelligence + MITRE
3. RAG service provides MITRE context to both Alert Triage AND CrewAI
4. Latency: End-to-end enrichment < 30 seconds
5. No duplicate IP analyses (caching works)

### 📊 Metrics to Track:
- Alerts enriched per hour
- Average IP analysis time
- Cache hit rate
- False positive reduction (before vs after IP intel)

---

## Next Steps

**RIGHT NOW:** We'll start with **Step 1.1** - Converting your CrewAI project to a FastAPI service.

**QUESTION:** Should I proceed with creating the FastAPI wrapper for your CrewAI crew?