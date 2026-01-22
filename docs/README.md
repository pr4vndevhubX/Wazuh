# Wazuh-CrewAI Threat Intelligence System
## AI-Powered Multi-Agent Security Operations Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Executive Summary

This project implements an advanced threat intelligence platform that integrates **Wazuh SIEM** with **CrewAI multi-agent framework** to automate security alert investigation and threat analysis. The system combines machine learning, large language models, and external threat intelligence APIs to provide comprehensive security event analysis with detailed PDF reports.

### Key Capabilities

- **Multi-Agent Investigation**: 10 specialized AI agents working collaboratively
- **External Threat Intelligence**: Integration with VirusTotal, AbuseIPDB, YETI
- **ML-Powered Classification**: Network traffic analysis with 99.28% accuracy
- **LLM Alert Triage**: Automated severity assessment and prioritization
- **MITRE ATT&CK Enrichment**: Contextual threat intelligence via RAG
- **Automated Reporting**: Professional PDF investigation reports
- **Real-Time Monitoring**: Prometheus + Grafana observability stack

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Architecture](#system-architecture)
3. [Current System Status](#current-system-status)
4. [Service Components](#service-components)
5. [CrewAI Agent System](#crewai-agent-system)
6. [Integration Workflow](#integration-workflow)
7. [API Endpoints](#api-endpoints)
8. [Monitoring & Observability](#monitoring--observability)
9. [Documentation](#documentation)
10. [Development Roadmap](#development-roadmap)

---

## Quick Start

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+, WSL2, or bare metal)
- **Memory**: 16GB RAM minimum (32GB recommended)
- **Storage**: 50GB available disk space
- **Docker**: Docker 24.0+ with Docker Compose V2
- **Python**: 3.11+ (for development/testing)

### 5-Minute Deployment

```bash
# 1. Clone repository
git clone <your-repository-url>
cd Threat-Intelligence-with-SIEM

# 2. Copy environment template
cp .env.example .env

# 3. Configure API keys (required)
nano .env
# Add: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, GROQ_API_KEY

# 4. Start all services
docker-compose up -d

# 5. Verify deployment
curl http://localhost:8002/health
```

### First Investigation

```bash
# Trigger a test investigation
curl -X POST http://localhost:8002/investigate/test-alert-001

# Check generated PDF report
ls -l reports/IOC_Report_*.pdf
```

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       WAZUH SIEM (Alert Source)                      │
│                    Port 1514 (Agent Communication)                   │
└────────────────────────────┬────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│              WAZUH INTEGRATION GATEWAY (Port 8002)                   │
│                      Smart Alert Router                              │
├─────────────────────────────────────────────────────────────────────┤
│  Routing Logic:                                                      │
│  • Level < 6   → Archive (no processing)                            │
│  • Level 6-7   → Dashboard only                                     │
│  • Level 8-9   → LLM Triage + Conditional Enrichment                │
│  • Level 10+   → Full Pipeline + Investigation Flag                 │
└────────────────────────────┬────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                   MICROSERVICES LAYER                                │
├─────────────────────────────────────────────────────────────────────┤
│  Alert Triage (8100)    RAG Service (8001)    ML Inference (8500)   │
│  • LLM Analysis         • MITRE ATT&CK KB     • Traffic Classify    │
│  • Severity Score       • 835 Techniques      • 99.28% Accuracy     │
│  • IOC Extraction       • Semantic Search     • 3ms Latency         │
└────────────────────────────┬────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│            CREWAI INVESTIGATION LAYER (Analyst-Triggered)            │
├─────────────────────────────────────────────────────────────────────┤
│  10 Specialized Agents:                                              │
│  1. Coordinator         6. ML Classifier                             │
│  2. VirusTotal          7. Alert Triage Analyst                      │
│  3. AbuseIPDB           8. MITRE Context                             │
│  4. YETI                9. Correlation Analyst                       │
│  5. SIEM Historian     10. Report Generator                          │
└────────────────────────────┬────────────────────────────────────────┘
                             ↓
                    ┌────────────────────┐
                    │   PDF Report       │
                    │   Generated        │
                    └────────────────────┘
```

### Data Flow

**Stage 1: Automatic Real-Time Processing**
```
Wazuh Alert → Integration Gateway → Severity Check
                                          ↓
                               ┌──────────┴─────────┐
                               ↓                    ↓
                        Level 8-9              Level 10+
                               ↓                    ↓
                        LLM Triage           Full Enrichment
                               ↓                    ↓
                    Conditional Enrichment   Flag for Investigation
                               ↓                    ↓
                          Dashboard            Dashboard + Queue
```

**Stage 2: Analyst-Triggered Investigation**
```
Analyst clicks "Investigate" → /investigate/{alert_id}
                                          ↓
                              CrewAI Orchestration
                                          ↓
                    ┌─────────────────────┴──────────────┐
                    ↓                                    ↓
            External Intel                      Internal Analysis
            • VirusTotal                        • SIEM History
            • AbuseIPDB                         • ML Prediction
            • YETI                              • LLM Triage
                    ↓                                    ↓
                    └──────────────┬──────────────────────┘
                                   ↓
                         Correlation Analysis
                                   ↓
                         MITRE ATT&CK Context
                                   ↓
                           PDF Report (90-120s)
```

---

## Current System Status

### ✅ Operational Services (100%)

| Service | Port | Status | Uptime | Health |
|---------|------|--------|--------|--------|
| **Alert Triage** | 8100 | Healthy | 3h+ | ✅ |
| **RAG Service** | 8001 | Healthy | 3h+ | ✅ |
| **ML Inference** | 8500 | Healthy | 3h+ | ✅ |
| **ChromaDB** | 8000 | Running | 3h+ | ✅ |
| **Ollama LLM** | 11434 | Running | 3h+ | ✅ |
| **Prometheus** | 9090 | Running | 3h+ | ✅ |
| **Loki** | 3100 | Running | 3h+ | ✅ |
| **Promtail** | - | Running | 3h+ | ✅ |

### 🚧 Services Pending Deployment

- **Wazuh Manager** - SIEM core (configuration pending)
- **Wazuh Indexer** - OpenSearch backend
- **Wazuh Dashboard** - Web UI
- **Grafana** - Metrics visualization (deployed separately)

### ⚠️ Known Port Discrepancy

Your services are running on **different ports** than the default configuration:

```python
# Current (Your Deployment)
Alert Triage: Port 8100 ✅
RAG Service:  Port 8001 ✅
ML Inference: Port 8500 ✅
```

**Action Required**: Update `main-wazuh-integration.py` port mappings.

---

## Service Components

### 1. Wazuh Integration Gateway (Port 8002)

**Purpose**: Central webhook receiver and smart alert router

**Key Features**:
- Receives alerts from Wazuh via webhook
- Severity-based routing logic
- Conditional microservice invocation
- Alert enrichment and storage
- Investigation queue management

**Endpoints**:
```
POST /webhook              - Receive Wazuh alerts
POST /investigate/{id}     - Trigger CrewAI investigation
GET  /health              - Service health check
GET  /metrics             - Prometheus metrics
```

**Configuration**: `main-wazuh-integration.py`

---

### 2. Alert Triage Service (Port 8100)

**Purpose**: LLM-powered alert severity assessment

**Technology**:
- Framework: FastAPI
- LLM: Ollama (llama3.2:3b - 2GB model)
- Response Time: 2-5 seconds

**Capabilities**:
- Severity classification (low/medium/high/critical)
- Confidence scoring (0.0 - 1.0)
- IOC extraction (IPs, domains, hashes)
- MITRE ATT&CK technique mapping
- Actionable recommendations

**API**:
```bash
POST /analyze
{
  "rule_id": "5710",
  "rule_description": "SSH brute force",
  "rule_level": 10,
  "source_ip": "192.168.1.100",
  "raw_log": "Failed password..."
}
```

**Response**:
```json
{
  "severity": "high",
  "confidence": 0.92,
  "is_true_positive": true,
  "iocs": [{"ioc_type": "ip", "value": "192.168.1.100"}],
  "mitre_techniques": ["T1110.001"],
  "recommendations": ["Block source IP", "Review logs"]
}
```

---

### 3. RAG Service (Port 8001)

**Purpose**: Semantic search over MITRE ATT&CK knowledge base

**Technology**:
- Vector DB: ChromaDB
- Embeddings: sentence-transformers
- Knowledge Base: 835 MITRE ATT&CK techniques

**Capabilities**:
- Semantic similarity search
- Technique retrieval with context
- Detection method recommendations
- Mitigation strategy suggestions

**API**:
```bash
POST /retrieve
{
  "query": "SSH brute force attack",
  "collection": "mitre_attack",
  "top_k": 5
}
```

**Response**:
```json
{
  "techniques_found": 5,
  "techniques": [
    {
      "technique_id": "T1110.001",
      "name": "Password Guessing",
      "tactic": "credential-access",
      "similarity_score": 0.89
    }
  ]
}
```

---

### 4. ML Inference Service (Port 8500)

**Purpose**: Network traffic classification

**Models**:
- Random Forest (99.28% accuracy)
- XGBoost (99.21% accuracy)
- Decision Tree (99.10% accuracy)

**Features**: 77-dimensional CICIDS2017 feature set

**API**:
```bash
POST /predict
{
  "features": [0.0, 0.0, ...],  # 77 features
  "model_name": "random_forest"
}
```

**Response**:
```json
{
  "prediction": "BENIGN",
  "confidence": 0.86,
  "model_used": "random_forest",
  "inference_time_ms": 3.2
}
```

---

### 5. Monitoring Stack

**Prometheus (Port 9090)**
- Metrics collection from all services
- 15-second scrape interval
- 30-day retention

**Loki (Port 3100)**
- Log aggregation
- Docker container logs
- 7-day retention

**Promtail**
- Log shipping agent
- Automatic Docker discovery
- Label extraction

**Grafana** (Deployed Separately)
- Metrics visualization
- Pre-built dashboards
- Alert management

---

## CrewAI Agent System

### Agent Architecture

The system employs **10 specialized agents** working in a **sequential workflow**:

```
┌──────────────────────────────────────────────────────────────┐
│  PHASE 1: COORDINATION & VALIDATION                          │
├──────────────────────────────────────────────────────────────┤
│  Agent 1: Coordinator                                        │
│  • Validates IP addresses                                    │
│  • Removes duplicates                                        │
│  • Prepares investigation scope                             │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  PHASE 2: EXTERNAL THREAT INTELLIGENCE (Parallel)            │
├──────────────────────────────────────────────────────────────┤
│  Agent 2: VirusTotal Specialist                              │
│  • Query 98+ antivirus vendors                               │
│  • Malicious detection count                                 │
│                                                              │
│  Agent 3: AbuseIPDB Analyst                                  │
│  • Community abuse reports                                   │
│  • Abuse confidence score                                    │
│                                                              │
│  Agent 4: YETI Platform Analyst                              │
│  • Internal threat intelligence                              │
│  • Historical context                                        │
│                                                              │
│  Agent 5: SIEM Historian                                     │
│  • Wazuh historical alerts                                   │
│  • Past activity timeline                                    │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  PHASE 3: AI/ML ENRICHMENT (Parallel)                        │
├──────────────────────────────────────────────────────────────┤
│  Agent 6: ML Classifier                                      │
│  • Network traffic prediction                                │
│  • Attack type classification                                │
│                                                              │
│  Agent 7: Alert Triage Analyst                               │
│  • LLM-based severity assessment                             │
│  • IOC extraction                                            │
│                                                              │
│  Agent 8: MITRE Context Analyst                              │
│  • ATT&CK technique mapping                                  │
│  • Detection/mitigation guidance                             │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  PHASE 4: CORRELATION & REPORTING                            │
├──────────────────────────────────────────────────────────────┤
│  Agent 9: Correlation Analyst                                │
│  • Synthesize all findings                                   │
│  • Threat verdict (BENIGN/CRITICAL)                          │
│  • Confidence scoring (0-100%)                               │
│                                                              │
│  Agent 10: Report Generator                                  │
│  • Professional PDF creation                                 │
│  • Executive summary                                         │
│  • Technical details                                         │
│  • Actionable recommendations                                │
└──────────────────────────────────────────────────────────────┘
```

### Agent Details

#### Agent 1: Threat Intelligence Coordinator
- **Role**: Orchestrate investigation workflow
- **Tools**: None (validation only)
- **Output**: Validated IP list

#### Agent 2: VirusTotal Reputation Specialist
- **Role**: Query VirusTotal API
- **Tools**: `VirusTotalTool`
- **Output**: Malicious count, reputation score

#### Agent 3: AbuseIPDB Analyst
- **Role**: Check community abuse reports
- **Tools**: `AbuseIPDBTool`
- **Output**: Abuse confidence, ISP info

#### Agent 4: Internal Threat Intelligence Analyst
- **Role**: Search YETI platform
- **Tools**: `YetiTool`
- **Output**: Tags, historical context

#### Agent 5: SIEM Historical Analyst
- **Role**: Query Wazuh database
- **Tools**: `WazuhSIEMTool`
- **Output**: Alert count, timeline

#### Agent 6: ML Traffic Classifier
- **Role**: Network behavior analysis
- **Tools**: `MLInferenceTool`
- **Output**: Attack prediction, confidence

#### Agent 7: LLM Alert Triage Specialist
- **Role**: Semantic alert analysis
- **Tools**: `AlertTriageTool`
- **Output**: Severity, IOCs, recommendations

#### Agent 8: MITRE ATT&CK Analyst
- **Role**: Technique contextualization
- **Tools**: `RAGMitreTool`
- **Output**: Relevant techniques, mitigations

#### Agent 9: Threat Correlation Analyst
- **Role**: Synthesize all intelligence
- **Tools**: None (analysis only)
- **Output**: Final verdict, confidence

#### Agent 10: Report Generator
- **Role**: Create investigation report
- **Tools**: None (PDF generation)
- **Output**: Comprehensive PDF report

---

## Integration Workflow

### Automatic Alert Processing (Real-Time)

```python
# Wazuh sends alert to webhook
POST http://localhost:8002/webhook
{
  "rule": {"level": 10, "description": "SSH brute force"},
  "data": {"srcip": "192.168.1.100"}
}

# Integration Gateway routing logic
if rule_level >= 8:
    triage_result = call_alert_triage(alert)
    
    if triage_result["severity"] in ["high", "critical"]:
        mitre_context = call_rag_service(alert)
        
        if source_ip:
            ml_prediction = call_ml_service(source_ip, alert)

# Store enriched alert
store_to_dashboard(enriched_alert)

# Flag for investigation if critical
if rule_level >= 10:
    flag_for_investigation(alert_id)
```

### Analyst-Triggered Investigation

```python
# Analyst clicks "Investigate" in dashboard
POST http://localhost:8002/investigate/alert-12345

# CrewAI orchestration begins
crew = IPIntelligenceCrew()
result = crew.kickoff(inputs={'ip_address': '192.168.1.100'})

# 90-120 seconds later...
# PDF report generated: reports/IOC_Report_192_168_1_100_20260120_173424.pdf
```

---

## API Endpoints

### Wazuh Integration Gateway (Port 8002)

```
POST /webhook
  Description: Receive Wazuh alerts
  Headers: X-API-Key: Apkl3@Jfyg2
  Body: Wazuh alert JSON
  Response: Enrichment status

POST /investigate/{alert_id}
  Description: Trigger CrewAI investigation
  Response: Investigation results + PDF path

GET /health
  Description: Service health check
  Response: {"status": "healthy", ...}

GET /metrics
  Description: Prometheus metrics
  Response: Metrics in Prometheus format
```

### Alert Triage Service (Port 8100)

```
POST /analyze
  Description: LLM-based alert analysis
  Body: Alert details
  Response: Severity, IOCs, recommendations

GET /health
  Description: Service health
  Response: {"status": "healthy"}
```

### RAG Service (Port 8001)

```
POST /retrieve
  Description: Semantic search MITRE ATT&CK
  Body: {"query": "...", "top_k": 5}
  Response: Relevant techniques

GET /health
  Description: Service health
  Response: {"status": "healthy"}
```

### ML Inference Service (Port 8500)

```
POST /predict
  Description: Network traffic classification
  Body: {"features": [...], "model_name": "..."}
  Response: Prediction, confidence

GET /health
  Description: Service health
  Response: {"status": "healthy"}
```

---

## Monitoring & Observability

### Metrics Collection

**Prometheus Scrape Targets**:
- Alert Triage: `http://localhost:8100/metrics`
- RAG Service: `http://localhost:8001/metrics`
- ML Inference: `http://localhost:8500/metrics`
- Integration Gateway: `http://localhost:8002/metrics`

**Key Metrics**:
```
wazuh_alerts_received_total{severity="critical|high|medium|low"}
crewai_executions_total{status="success|error"}
crewai_execution_duration_seconds
alert_triage_calls_total{status="success|timeout|error"}
enrichment_calls_total{service="rag|ml", status="success|error"}
```

### Log Aggregation

**Loki + Promtail**:
- All Docker container logs
- Searchable via Grafana Explore
- 7-day retention

**Query Examples**:
```
{container_name="alert-triage"} |= "error"
{container_name=~"rag-service|ml-inference"} |= "predict"
```

---

## Documentation

### Complete Documentation Set

1. **[QUICKSTART.md](QUICKSTART.md)** - 5-minute deployment guide
2. **[INSTALLATION.md](INSTALLATION.md)** - Detailed setup instructions
3. **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and data flow
4. **[API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation
5. **[MONITORING.md](MONITORING.md)** - Observability and metrics
6. **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and fixes
7. **[DEVELOPMENT.md](DEVELOPMENT.md)** - Developer guide
8. **[ROADMAP.md](ROADMAP.md)** - Future development plan

---

## Development Roadmap

### Phase 1: Core Infrastructure ✅ (Complete)
- [x] Wazuh Integration Gateway
- [x] Alert Triage Service
- [x] RAG Service with MITRE ATT&CK
- [x] ML Inference Service
- [x] CrewAI Agent Orchestration
- [x] Monitoring Stack

### Phase 2: Production Deployment 🚧 (In Progress)
- [ ] Deploy Wazuh SIEM
- [ ] Fix port mappings (8001→8200, 8500→8300)
- [ ] Configure Wazuh webhook integration
- [ ] Implement database persistence
- [ ] Build SOC Dashboard UI

### Phase 3: Advanced Features (Planned)
- [ ] Multi-class ML classification (24 attack types)
- [ ] Automated incident response playbooks
- [ ] Threat hunting workflows
- [ ] Custom detection rules engine
- [ ] Integration with ticketing systems

### Phase 4: Scale & Optimize (Future)
- [ ] Kubernetes deployment
- [ ] Horizontal scaling
- [ ] Performance optimization
- [ ] Advanced caching strategies
- [ ] Multi-tenant support

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## Contact

**Author**: [Your Name]
**Email**: [your.email@example.com]
**Repository**: [GitHub URL]

---

**Last Updated**: 2026-01-20
**Version**: 1.0.0
**Status**: Production-Ready (80% Complete)