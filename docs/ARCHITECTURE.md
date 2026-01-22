# System Architecture
## Wazuh-CrewAI Threat Intelligence Platform

Comprehensive system design and technical architecture documentation.

---

## Table of Contents

1. [Architectural Overview](#architectural-overview)
2. [Design Principles](#design-principles)
3. [Component Architecture](#component-architecture)
4. [Data Flow](#data-flow)
5. [Network Topology](#network-topology)
6. [Agent Orchestration](#agent-orchestration)
7. [Integration Patterns](#integration-patterns)
8. [Scalability Considerations](#scalability-considerations)

---

## Architectural Overview

### High-Level System Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                            │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Wazuh Dashboard │  │ SOC Dashboard│  │ Grafana Metrics  │   │
│  │   (Port 443)    │  │  (Future)    │  │   (Port 3000)    │   │
│  └─────────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  INTEGRATION & ROUTING LAYER                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │         Wazuh Integration Gateway (Port 8002)             │  │
│  │  • Smart alert routing by severity                        │  │
│  │  • Microservice orchestration                             │  │
│  │  • Investigation queue management                         │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   AI/ML SERVICES LAYER                           │
│  ┌──────────────┐  ┌─────────────────┐  ┌──────────────────┐   │
│  │Alert Triage  │  │  RAG Service    │  │  ML Inference    │   │
│  │ (Port 8100)  │  │  (Port 8001)    │  │  (Port 8500)     │   │
│  │              │  │                 │  │                  │   │
│  │ • LLM        │  │ • ChromaDB      │  │ • RandomForest   │   │
│  │ • Ollama     │  │ • MITRE KB      │  │ • XGBoost        │   │
│  │ • IOC        │  │ • Semantic      │  │ • 99.28% Acc     │   │
│  │   Extract    │  │   Search        │  │ • 3ms Latency    │   │
│  └──────────────┘  └─────────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              CREWAI ORCHESTRATION LAYER                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  10 Specialized Agents (Sequential Workflow)              │  │
│  │  • Coordinator → External Intel → AI Analysis            │  │
│  │  • Correlation → Report Generation                        │  │
│  │  Execution Time: 90-120 seconds                           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    DATA SOURCES LAYER                            │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐  │
│  │ VirusTotal │  │ AbuseIPDB  │  │   YETI     │  │  Wazuh   │  │
│  │    API     │  │    API     │  │ Platform   │  │  SIEM    │  │
│  └────────────┘  └────────────┘  └────────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                 PERSISTENCE & MONITORING LAYER                   │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌─────────────┐   │
│  │ ChromaDB │  │Prometheus │  │   Loki    │  │  Docker     │   │
│  │ (Vectors)│  │ (Metrics) │  │  (Logs)   │  │  Volumes    │   │
│  └──────────┘  └───────────┘  └───────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Design Principles

### 1. Separation of Concerns

Each service has a **single, well-defined responsibility**:

- **Integration Gateway**: Alert routing and orchestration
- **Alert Triage**: LLM-based severity assessment
- **RAG Service**: Knowledge base retrieval
- **ML Inference**: Network traffic classification
- **CrewAI**: Comprehensive investigation orchestration

### 2. Microservices Architecture

**Benefits**:
- Independent deployment and scaling
- Technology flexibility (Python FastAPI, Ollama, Groq)
- Fault isolation (one service failure doesn't crash system)
- Easy maintenance and updates

**Communication**: RESTful APIs with JSON payloads

### 3. Stateless Services

All services are **stateless** (except databases):
- No session storage in services
- Horizontal scaling possible
- Easy recovery from failures
- Configuration via environment variables

### 4. Graceful Degradation

System continues operating when services fail:

```python
try:
    triage_result = call_alert_triage(alert)
except ServiceUnavailable:
    triage_result = {"severity": "unknown", "service": "unavailable"}
    # Continue with other enrichments
```

**Example**: If RAG service is down, investigation still completes using other sources.

### 5. Observability-First

Every service exposes:
- `/health` endpoint for liveness checks
- `/metrics` endpoint for Prometheus
- Structured logging to stdout (collected by Loki)

---

## Component Architecture

### Integration Gateway (Port 8002)

**Technology**: Python 3.11 + FastAPI + Uvicorn

**Responsibilities**:
1. Receive Wazuh alerts via webhook
2. Route alerts based on severity
3. Call microservices conditionally
4. Store enriched alerts
5. Queue critical alerts for investigation

**Routing Logic**:

```python
if rule_level < 6:
    return archive()
    
elif rule_level < 8:
    store_to_dashboard(alert)
    return {"status": "dashboard_only"}
    
elif rule_level >= 8:
    # Always run LLM triage
    triage = call_alert_triage(alert)
    
    if triage["severity"] in ["high", "critical"]:
        # Conditional enrichment
        mitre = call_rag_service(alert)
        
        if source_ip:
            ml = call_ml_service(source_ip)
    
    if rule_level >= 10:
        flag_for_investigation(alert_id)
```

**API Endpoints**:
```
POST /webhook              - Receive alerts
POST /investigate/{id}     - Trigger investigation
GET  /health              - Health check
GET  /metrics             - Prometheus metrics
```

---

### Alert Triage Service (Port 8100)

**Technology**: Python 3.11 + FastAPI + Ollama

**Architecture**:

```
┌──────────────────────────────────────────────────┐
│          Alert Triage Service                    │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌─────────────────────────────────────────┐    │
│  │  FastAPI Application                     │    │
│  │  • POST /analyze                         │    │
│  │  • POST /batch                           │    │
│  │  • GET  /health                          │    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  LLM Client (Ollama Integration)         │    │
│  │  • Model: llama3.2:3b (2GB)              │    │
│  │  • Context: 4096 tokens                  │    │
│  │  • Prompt engineering for IOC extraction│    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  Response Parser                         │    │
│  │  • JSON extraction                       │    │
│  │  • Confidence scoring                    │    │
│  │  • MITRE technique mapping               │    │
│  └─────────────────────────────────────────┘    │
│                                                  │
└──────────────────────────────────────────────────┘
                    ↓
        External: Ollama Server (Port 11434)
```

**Processing Flow**:

1. **Receive Alert**: Wazuh alert JSON payload
2. **Feature Extraction**: Extract key fields (rule_id, IP, description)
3. **Prompt Construction**: Build context-aware prompt
4. **LLM Inference**: Call Ollama API
5. **Response Parsing**: Extract structured data from LLM output
6. **Validation**: Ensure JSON schema compliance
7. **Return Result**: Severity, confidence, IOCs, recommendations

**LLM Prompt Template**:

```python
prompt = f"""
You are a cybersecurity analyst. Analyze this security alert:

Rule: {rule_description}
Severity Level: {rule_level}/15
Source IP: {source_ip}
Raw Log: {raw_log}

Provide analysis in JSON format:
{{
  "severity": "low|medium|high|critical",
  "confidence": 0.0-1.0,
  "is_true_positive": true/false,
  "iocs": [{"ioc_type": "ip", "value": "..."}}],
  "mitre_techniques": ["T1XXX"],
  "recommendations": ["..."]
}}
"""
```

---

### RAG Service (Port 8001)

**Technology**: Python 3.11 + FastAPI + ChromaDB + Sentence Transformers

**Architecture**:

```
┌──────────────────────────────────────────────────┐
│             RAG Service                          │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌─────────────────────────────────────────┐    │
│  │  FastAPI Application                     │    │
│  │  • POST /retrieve                        │    │
│  │  • POST /ingest                          │    │
│  │  • GET  /health                          │    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  Embedding Generation                    │    │
│  │  • Model: sentence-transformers          │    │
│  │  • all-MiniLM-L6-v2 (22M params)         │    │
│  │  • 384-dimensional vectors               │    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  ChromaDB Vector Store                   │    │
│  │  • Collection: mitre_attack              │    │
│  │  • 835 MITRE ATT&CK techniques           │    │
│  │  • Cosine similarity search              │    │
│  └─────────────────────────────────────────┘    │
│                                                  │
└──────────────────────────────────────────────────┘
                    ↓
        External: ChromaDB Server (Port 8000)
```

**Knowledge Base Structure**:

```json
{
  "technique_id": "T1110.001",
  "name": "Password Guessing",
  "tactic": "credential-access",
  "description": "Adversaries may use brute force techniques...",
  "detection": "Monitor authentication logs for repeated failures...",
  "mitigation": "Implement account lockout policies...",
  "platforms": ["Windows", "Linux", "macOS"],
  "embedding": [0.123, -0.456, ...]  // 384-dim vector
}
```

**Retrieval Process**:

1. **Query Received**: "SSH brute force attack"
2. **Generate Embedding**: Query → 384-dim vector
3. **Similarity Search**: Find top-k nearest neighbors in ChromaDB
4. **Re-ranking**: Apply relevance scoring
5. **Context Enrichment**: Add detection/mitigation details
6. **Return Results**: Top-k techniques with metadata

---

### ML Inference Service (Port 8500)

**Technology**: Python 3.11 + FastAPI + Scikit-learn

**Architecture**:

```
┌──────────────────────────────────────────────────┐
│          ML Inference Service                    │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌─────────────────────────────────────────┐    │
│  │  FastAPI Application                     │    │
│  │  • POST /predict                         │    │
│  │  • POST /batch_predict                   │    │
│  │  • GET  /models                          │    │
│  │  • GET  /health                          │    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  Model Manager                           │    │
│  │  • RandomForest (99.28% acc)             │    │
│  │  • XGBoost (99.21% acc)                  │    │
│  │  • DecisionTree (99.10% acc)             │    │
│  │  • Lazy loading (loaded on first use)   │    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  Feature Engineering                     │    │
│  │  • 77-dimensional CICIDS2017 features    │    │
│  │  • StandardScaler normalization          │    │
│  │  • Missing value handling                │    │
│  └─────────────────┬───────────────────────┘    │
│                    ↓                             │
│  ┌─────────────────────────────────────────┐    │
│  │  Inference Engine                        │    │
│  │  • Batch prediction support              │    │
│  │  • Confidence scoring                    │    │
│  │  • Performance monitoring                │    │
│  └─────────────────────────────────────────┘    │
│                                                  │
└──────────────────────────────────────────────────┘
```

**Models**:

| Model | Accuracy | Precision | Recall | Inference Time |
|-------|----------|-----------|--------|----------------|
| RandomForest | 99.28% | 99.29% | 99.28% | 0.8ms |
| XGBoost | 99.21% | 99.23% | 99.21% | 0.3ms |
| DecisionTree | 99.10% | 99.13% | 99.10% | 0.2ms |

**Feature Vector** (77 dimensions):
- Flow duration
- Packet counts (fwd/bwd)
- Byte counts (fwd/bwd)
- Packet length stats (min/max/mean/std)
- Inter-arrival times
- TCP flags
- Active/idle times

---

### CrewAI Orchestration

**Technology**: Python 3.11 + CrewAI + Groq LLM

**Agent Execution Flow**:

```
START (IP: 8.8.8.8)
    ↓
┌───────────────────────────────────────────┐
│ PHASE 1: Coordinator (5s)                 │
│ • Validate IP format                      │
│ • Remove duplicates                       │
│ • Prepare investigation scope             │
└───────────────┬───────────────────────────┘
                ↓
┌───────────────────────────────────────────────────────────┐
│ PHASE 2: External Intel (Parallel, 15s)                   │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│ │ VirusTotal   │  │ AbuseIPDB    │  │ YETI + SIEM     │ │
│ │ • 0/97 clean │  │ • 0% abuse   │  │ • Auth failed   │ │
│ └──────────────┘  └──────────────┘  └──────────────────┘ │
└───────────────┬───────────────────────────────────────────┘
                ↓
┌───────────────────────────────────────────────────────────┐
│ PHASE 3: AI Enrichment (Parallel, 20s)                    │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│ │ ML Classify  │  │Alert Triage  │  │ MITRE Context   │ │
│ │ • BENIGN 86% │  │ • Fallback   │  │ • 5 techniques  │ │
│ └──────────────┘  └──────────────┘  └──────────────────┘ │
└───────────────┬───────────────────────────────────────────┘
                ↓
┌───────────────────────────────────────────┐
│ PHASE 4: Correlation (30s)                │
│ • Synthesize all findings                 │
│ • Calculate threat score                  │
│ • Verdict: BENIGN (96% confidence)        │
└───────────────┬───────────────────────────┘
                ↓
┌───────────────────────────────────────────┐
│ PHASE 5: Report Generation (40s)          │
│ • Create PDF report                       │
│ • Executive summary                       │
│ • Technical details                       │
│ • Recommendations                         │
└───────────────┬───────────────────────────┘
                ↓
END (Total: 90-120s)
PDF: reports/IOC_Report_8_8_8_8_*.pdf
```

---

## Data Flow

### Alert Processing Pipeline

```
Wazuh Agent → Wazuh Manager → Integration Gateway
                                      ↓
                            Route by Severity
                                      ↓
                    ┌─────────────────┴─────────────────┐
                    ↓                                   ↓
              Level < 8                            Level >= 8
                    ↓                                   ↓
              Dashboard Only                    LLM Triage
                                                        ↓
                                          ┌─────────────┴────────────┐
                                          ↓                          ↓
                                    Severity Low             Severity High
                                          ↓                          ↓
                                    Dashboard        RAG + ML Enrichment
                                                               ↓
                                                     ┌─────────┴─────────┐
                                                     ↓                   ↓
                                               Level < 10          Level >= 10
                                                     ↓                   ↓
                                               Dashboard         Flag for Invest
                                                                        ↓
                                                              Investigation Queue
```

### Investigation Data Flow

```
Analyst clicks "Investigate"
         ↓
Integration Gateway: /investigate/{alert_id}
         ↓
Retrieve Alert from Database
         ↓
Extract IP Address
         ↓
CrewAI Kickoff
         ↓
┌────────────────────────────────────┐
│  Sequential Agent Execution        │
├────────────────────────────────────┤
│  Agent 1: Coordinator              │
│    Output → Agent 2-5 (context)    │
│                                    │
│  Agent 2-5: External Intel         │
│    Outputs → Agent 9 (context)     │
│                                    │
│  Agent 6-8: AI Enrichment          │
│    Outputs → Agent 9 (context)     │
│                                    │
│  Agent 9: Correlation              │
│    Output → Agent 10 (context)     │
│                                    │
│  Agent 10: Report Generator        │
│    Output → Final Report           │
└────────────────────────────────────┘
         ↓
PDF Report Generated
         ↓
Store Investigation Results
         ↓
Return Response to Analyst
```

---

## Network Topology

### Docker Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Docker Host (172.17.0.0/16 - default bridge)               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │  ai-services Network (172.30.0.0/24)               │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────┐  │    │
│  │  │alert-triage  │  │rag-service   │  │ ollama  │  │    │
│  │  │172.30.0.2    │  │172.30.0.3    │  │172.30.0.4│ │    │
│  │  └──────────────┘  └──────────────┘  └─────────┘  │    │
│  │  ┌──────────────┐  ┌──────────────┐               │    │
│  │  │ids-inference │  │chromadb      │               │    │
│  │  │172.30.0.5    │  │172.30.0.6    │               │    │
│  │  └──────────────┘  └──────────────┘               │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │  monitoring Network (172.40.0.0/24)                │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────┐  │    │
│  │  │prometheus    │  │loki          │  │promtail │  │    │
│  │  │172.40.0.2    │  │172.40.0.3    │  │172.40.0.4│ │    │
│  │  └──────────────┘  └──────────────┘  └─────────┘  │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Host Network (wazuh-integration)                  │    │
│  │  • Runs on host: 0.0.0.0:8002                      │    │
│  │  • Accesses Docker services via host.docker.internal│
│  └────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Port Mapping

| Service | Internal Port | External Port | Protocol |
|---------|---------------|---------------|----------|
| Alert Triage | 8000 | 8100 | HTTP |
| RAG Service | 8000 | 8001 | HTTP |
| ML Inference | 8000 | 8500 | HTTP |
| ChromaDB | 8000 | 8000 | HTTP |
| Ollama | 11434 | - | HTTP |
| Prometheus | 9090 | 9090 | HTTP |
| Loki | 3100 | 3100 | HTTP |
| Integration Gateway | 8002 | 8002 | HTTP |

---

## Agent Orchestration

### Sequential vs Parallel Execution

**CrewAI Sequential Process**:

```python
crew = Crew(
    agents=[...],  # 10 agents
    tasks=[...],   # 10 tasks
    process=Process.sequential,  # Sequential execution
    memory=False,  # Stateless
    cache=True     # Cache LLM responses
)
```

**Why Sequential?**
- **Context Passing**: Each agent builds on previous outputs
- **Dependency Management**: Later agents need earlier results
- **Predictable Execution**: Linear workflow easier to debug
- **Resource Efficiency**: One agent active at a time

**Task Dependencies**:

```python
task_correlation = Task(
    agent=correlation_analyst,
    context=[  # Requires these tasks to complete first
        task_coordinator,
        task_virustotal,
        task_abuseipdb,
        task_yeti,
        task_siem,
        task_ml_classification,
        task_alert_triage,
        task_mitre_context
    ]
)
```

### Agent Communication

```
Agent N Output
      ↓
CrewAI Context Manager
      ↓
Agent N+1 Input (via context)
```

**Example**:

```python
# Coordinator output
coordinator_output = "Valid IPs: ['8.8.8.8']"

# VirusTotal receives this in context
virustotal_task.context = [task_coordinator]

# Agent can reference coordinator findings
"Based on the coordinator's validation, analyze IP: 8.8.8.8"
```

---

## Integration Patterns

### 1. Webhook Pattern (Wazuh → Integration Gateway)

```python
@app.post("/webhook")
async def receive_alert(alert: dict, x_api_key: str):
    # Authentication
    if x_api_key != "Apkl3@Jfyg2":
        raise HTTPException(401)
    
    # Process asynchronously
    background_tasks.add_task(process_alert, alert)
    
    # Immediate response
    return {"status": "accepted"}
```

### 2. Service-to-Service (Integration Gateway → Microservices)

```python
async def call_alert_triage(alert: dict) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8100/analyze",
            json=alert,
            timeout=10.0
        )
        return response.json()
```

### 3. Agent-to-Tool (CrewAI → External APIs)

```python
class VirusTotalTool(BaseTool):
    def _run(self, ip_address: str) -> dict:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": API_KEY}
        )
        return response.json()
```

---

## Scalability Considerations

### Horizontal Scaling

**Stateless Services** can be replicated:

```yaml
services:
  alert-triage:
    image: alert-triage:latest
    deploy:
      replicas: 3  # Run 3 instances
      resources:
        limits:
          cpus: '2'
          memory: 4G
```

**Load Balancing** (with Nginx):

```nginx
upstream alert_triage {
    server alert-triage-1:8000;
    server alert-triage-2:8000;
    server alert-triage-3:8000;
}
```

### Vertical Scaling

**Resource Allocation**:

```yaml
services:
  ml-inference:
    deploy:
      resources:
        limits:
          cpus: '4'      # Increase CPU
          memory: 8G     # Increase RAM
```

### Database Scaling

**ChromaDB** → **Qdrant** (production):
- Distributed deployment
- Sharding support
- Replication

**Future**: Multi-tenant with namespace isolation

---

## Security Architecture

### Authentication Layers

```
External Request
      ↓
API Key Validation (Integration Gateway)
      ↓
Service-to-Service (Internal Network)
      ↓
External API Keys (VirusTotal, AbuseIPDB)
```

### Network Isolation

- **Public**: Integration Gateway (8002), Grafana (3000)
- **Internal**: All AI services, databases
- **External**: External API calls (VirusTotal, AbuseIPDB)

---

**Last Updated**: 2026-01-20
**Next**: See [API_REFERENCE.md](API_REFERENCE.md) for endpoint specifications