# API Reference
## Wazuh-CrewAI Threat Intelligence System

Complete API documentation for all services.

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Wazuh Integration Gateway API](#wazuh-integration-gateway-api)
4. [Alert Triage Service API](#alert-triage-service-api)
5. [RAG Service API](#rag-service-api)
6. [ML Inference Service API](#ml-inference-service-api)
7. [Error Handling](#error-handling)
8. [Rate Limits](#rate-limits)
9. [API Examples](#api-examples)

---

## Overview

### Base URLs

| Service | Base URL | Protocol |
|---------|----------|----------|
| **Wazuh Integration** | `http://localhost:8002` | HTTP |
| **Alert Triage** | `http://localhost:8100` | HTTP |
| **RAG Service** | `http://localhost:8001` | HTTP |
| **ML Inference** | `http://localhost:8500` | HTTP |

### Response Format

All APIs return JSON responses with the following structure:

**Success Response**:
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": "2026-01-20T17:34:56Z"
}
```

**Error Response**:
```json
{
  "status": "error",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid IP address format",
    "details": { ... }
  },
  "timestamp": "2026-01-20T17:34:56Z"
}
```

---

## Authentication

### Wazuh Integration Gateway

**API Key Authentication** (Header-based):

```bash
curl -X POST http://localhost:8002/webhook \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -H "Content-Type: application/json"
```

**Default API Key**: `Apkl3@Jfyg2` (Change in production!)

**Update API Key**:
Edit `.env` file:
```bash
WAZUH_INTEGRATION_API_KEY=your_secure_key_here
```

### Other Services

**No Authentication** (Internal services):
- Alert Triage Service
- RAG Service
- ML Inference Service

**Production**: Deploy behind reverse proxy with TLS + authentication.

---

## Wazuh Integration Gateway API

### POST /webhook

Receive and process Wazuh alerts.

**Endpoint**: `POST /webhook`

**Headers**:
```
Content-Type: application/json
X-API-Key: Apkl3@Jfyg2
```

**Request Body**:
```json
{
  "id": "1737389400.12345",
  "timestamp": "2026-01-20T12:30:00.000Z",
  "rule": {
    "level": 10,
    "description": "SSH brute force attack detected",
    "id": "5710",
    "groups": ["authentication_failed", "sshd"]
  },
  "data": {
    "srcip": "192.168.1.100",
    "dstip": "10.0.0.5",
    "srcport": 45678,
    "dstport": 22
  },
  "agent": {
    "id": "001",
    "name": "web-server-01"
  }
}
```

**Response** (Level < 6):
```json
{
  "status": "archived",
  "reason": "level < 6",
  "action": "none"
}
```

**Response** (Level 6-7):
```json
{
  "status": "dashboard_stored",
  "reason": "level 6-7",
  "action": "metrics_only"
}
```

**Response** (Level 8-9):
```json
{
  "status": "processed",
  "alert_id": "1737389400.12345",
  "rule_level": 8,
  "triage_severity": "high",
  "enrichments_applied": ["triage", "mitre", "ml"],
  "flagged_for_investigation": false
}
```

**Response** (Level 10+):
```json
{
  "status": "processed",
  "alert_id": "1737389400.12345",
  "rule_level": 12,
  "triage_severity": "critical",
  "enrichments_applied": ["triage", "mitre", "ml"],
  "flagged_for_investigation": true
}
```

**HTTP Status Codes**:
- `200 OK` - Alert processed successfully
- `401 Unauthorized` - Invalid API key
- `422 Unprocessable Entity` - Invalid alert format
- `500 Internal Server Error` - Processing error

---

### POST /investigate/{alert_id}

Trigger full CrewAI investigation for a specific alert.

**Endpoint**: `POST /investigate/{alert_id}`

**Parameters**:
- `alert_id` (path) - Alert identifier (e.g., "1737389400.12345")

**Headers**:
```
Content-Type: application/json
```

**Request Body**: None (alert_id in path)

**Example**:
```bash
curl -X POST http://localhost:8002/investigate/1737389400.12345
```

**Response**:
```json
{
  "status": "success",
  "alert_id": "1737389400.12345",
  "ip_address": "192.168.1.100",
  "pdf_report": "reports/IOC_Report_192_168_1_100_20260120_173456.pdf",
  "execution_time": "102.97s",
  "raw_result": "🔵 IOC Investigation Report\n**Target IP:** 192.168.1.100\n..."
}
```

**HTTP Status Codes**:
- `200 OK` - Investigation completed
- `404 Not Found` - Alert ID not found
- `400 Bad Request` - No source IP in alert
- `500 Internal Server Error` - Investigation failed

**Execution Time**: 90-120 seconds (all 10 agents)

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "wazuh-integration",
  "timestamp": "2026-01-20T17:34:56.084268"
}
```

**HTTP Status Codes**:
- `200 OK` - Service healthy
- `503 Service Unavailable` - Service unhealthy

---

### GET /metrics

Prometheus metrics endpoint.

**Endpoint**: `GET /metrics`

**Response** (Prometheus format):
```
# HELP wazuh_alerts_received_total Total alerts received from Wazuh
# TYPE wazuh_alerts_received_total counter
wazuh_alerts_received_total{severity="critical"} 15.0
wazuh_alerts_received_total{severity="high"} 42.0
wazuh_alerts_received_total{severity="medium"} 128.0

# HELP crewai_executions_total Total CrewAI agent executions
# TYPE crewai_executions_total counter
crewai_executions_total{status="success"} 8.0
crewai_executions_total{status="error"} 1.0

# HELP crewai_execution_duration_seconds Time spent executing CrewAI analysis
# TYPE crewai_execution_duration_seconds histogram
crewai_execution_duration_seconds_bucket{le="60.0"} 2.0
crewai_execution_duration_seconds_bucket{le="120.0"} 7.0
crewai_execution_duration_seconds_sum 856.32
crewai_execution_duration_seconds_count 8.0
```

---

## Alert Triage Service API

### POST /analyze

Analyze security alert using LLM.

**Endpoint**: `POST /analyze`

**Request Body**:
```json
{
  "alert_id": "test-001",
  "timestamp": "2026-01-20T12:00:00Z",
  "rule_id": "5710",
  "rule_description": "SSH brute force attack detected",
  "rule_level": 10,
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.5",
  "source_port": 45678,
  "dest_port": 22,
  "raw_log": "Failed password for root from 192.168.1.100 port 45678 ssh2"
}
```

**Response**:
```json
{
  "alert_id": "test-001",
  "severity": "high",
  "confidence": 0.92,
  "is_true_positive": true,
  "category": "intrusion_attempt",
  "summary": "SSH brute force attack detected from external IP. Multiple failed authentication attempts indicate credential guessing attack.",
  "iocs": [
    {
      "ioc_type": "ip",
      "value": "192.168.1.100",
      "confidence": 0.95
    },
    {
      "ioc_type": "port",
      "value": "22",
      "context": "SSH service targeted"
    }
  ],
  "mitre_techniques": [
    "T1110.001"
  ],
  "recommendations": [
    {
      "action": "Block source IP at firewall",
      "priority": 1,
      "rationale": "Prevent further brute force attempts"
    },
    {
      "action": "Review SSH logs for compromise indicators",
      "priority": 2,
      "rationale": "Check if any logins succeeded"
    },
    {
      "action": "Enable fail2ban if not configured",
      "priority": 3,
      "rationale": "Automated blocking of brute force attempts"
    }
  ],
  "model_used": "llama3.2:3b",
  "processing_time_ms": 2847
}
```

**HTTP Status Codes**:
- `200 OK` - Analysis completed
- `422 Unprocessable Entity` - Invalid request format
- `503 Service Unavailable` - LLM service unavailable

---

### POST /batch

Batch alert analysis (up to 100 alerts).

**Endpoint**: `POST /batch`

**Request Body**:
```json
{
  "alerts": [
    {
      "alert_id": "test-001",
      "rule_description": "SSH brute force",
      "rule_level": 10,
      "source_ip": "192.168.1.100"
    },
    {
      "alert_id": "test-002",
      "rule_description": "SQL injection attempt",
      "rule_level": 12,
      "source_ip": "203.0.113.42"
    }
  ]
}
```

**Response**:
```json
{
  "results": [
    {
      "alert_id": "test-001",
      "severity": "high",
      "confidence": 0.92
    },
    {
      "alert_id": "test-002",
      "severity": "critical",
      "confidence": 0.98
    }
  ],
  "total_processed": 2,
  "total_time_ms": 5632
}
```

**Limits**: Maximum 100 alerts per request

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "alert-triage",
  "llm_available": true,
  "model": "llama3.2:3b"
}
```

---

## RAG Service API

### POST /retrieve

Retrieve relevant MITRE ATT&CK techniques via semantic search.

**Endpoint**: `POST /retrieve`

**Request Body**:
```json
{
  "query": "SSH brute force credential guessing",
  "collection": "mitre_attack",
  "top_k": 5,
  "min_similarity": 0.3
}
```

**Response**:
```json
{
  "techniques_found": 5,
  "query_used": "SSH brute force credential guessing",
  "collection": "mitre_attack",
  "service_status": "available",
  "results": [
    {
      "technique_id": "T1110.001",
      "name": "Password Guessing",
      "tactic": "credential-access",
      "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained...",
      "similarity_score": 0.89,
      "platforms": ["Windows", "Linux", "macOS"],
      "detection": "Monitor authentication logs for system and application login failures of Valid Accounts...",
      "mitigation": "Refer to NIST guidelines when creating password policies..."
    },
    {
      "technique_id": "T1021.004",
      "name": "SSH",
      "tactic": "lateral-movement",
      "description": "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH)...",
      "similarity_score": 0.76,
      "platforms": ["Linux", "macOS"]
    }
  ]
}
```

**Parameters**:
- `query` (required) - Search query string
- `collection` (optional) - Collection name (default: "mitre_attack")
- `top_k` (optional) - Number of results (default: 5, max: 20)
- `min_similarity` (optional) - Minimum similarity threshold (default: 0.3)

**HTTP Status Codes**:
- `200 OK` - Retrieval successful
- `400 Bad Request` - Invalid query format
- `503 Service Unavailable` - ChromaDB unavailable

---

### POST /ingest

Ingest new documents into knowledge base (Admin only).

**Endpoint**: `POST /ingest`

**Request Body**:
```json
{
  "collection": "mitre_attack",
  "documents": [
    {
      "technique_id": "T1234",
      "name": "Custom Technique",
      "description": "Technique description...",
      "tactic": "execution",
      "platforms": ["Windows"]
    }
  ]
}
```

**Response**:
```json
{
  "status": "success",
  "documents_ingested": 1,
  "collection": "mitre_attack"
}
```

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "rag-service",
  "chromadb_available": true,
  "collections": ["mitre_attack"],
  "total_documents": 835
}
```

---

## ML Inference Service API

### POST /predict

Classify network traffic using ML models.

**Endpoint**: `POST /predict`

**Request Body**:
```json
{
  "features": [
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    // ... 77 total features
  ],
  "model_name": "random_forest"
}
```

**Feature Vector** (77 dimensions):
1. Flow Duration
2. Total Fwd Packets
3. Total Backward Packets
4. Total Length of Fwd Packets
5. Total Length of Bwd Packets
6. Fwd Packet Length Max
7. Fwd Packet Length Min
8. Fwd Packet Length Mean
9. Fwd Packet Length Std
10. Bwd Packet Length Max
... (see full list in model documentation)

**Response**:
```json
{
  "prediction": "BENIGN",
  "confidence": 0.86,
  "model_used": "random_forest",
  "probabilities": {
    "BENIGN": 0.86,
    "ATTACK": 0.14
  },
  "inference_time_ms": 3.2,
  "feature_count": 77
}
```

**Supported Models**:
- `random_forest` - RandomForest (99.28% accuracy)
- `xgboost` - XGBoost (99.21% accuracy)
- `decision_tree` - DecisionTree (99.10% accuracy)

**HTTP Status Codes**:
- `200 OK` - Prediction successful
- `422 Unprocessable Entity` - Invalid feature vector
- `503 Service Unavailable` - Model not loaded

---

### POST /batch_predict

Batch prediction (up to 1000 samples).

**Endpoint**: `POST /batch_predict`

**Request Body**:
```json
{
  "samples": [
    {
      "id": "flow-001",
      "features": [0.0, 0.0, ...]
    },
    {
      "id": "flow-002",
      "features": [0.0, 0.0, ...]
    }
  ],
  "model_name": "random_forest"
}
```

**Response**:
```json
{
  "predictions": [
    {
      "id": "flow-001",
      "prediction": "BENIGN",
      "confidence": 0.86
    },
    {
      "id": "flow-002",
      "prediction": "ATTACK",
      "confidence": 0.94
    }
  ],
  "total_samples": 2,
  "total_time_ms": 12.5
}
```

---

### GET /models

List available models.

**Endpoint**: `GET /models`

**Response**:
```json
{
  "models": [
    {
      "name": "random_forest",
      "accuracy": 0.9928,
      "loaded": true
    },
    {
      "name": "xgboost",
      "accuracy": 0.9921,
      "loaded": true
    },
    {
      "name": "decision_tree",
      "accuracy": 0.9910,
      "loaded": false
    }
  ]
}
```

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "ml-inference",
  "models_loaded": 3,
  "default_model": "random_forest"
}
```

---

## Error Handling

### Standard Error Response

```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "specific_field",
      "reason": "validation_failed"
    }
  },
  "timestamp": "2026-01-20T17:34:56Z"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_API_KEY` | 401 | API key missing or invalid |
| `VALIDATION_ERROR` | 422 | Request validation failed |
| `NOT_FOUND` | 404 | Resource not found |
| `SERVICE_UNAVAILABLE` | 503 | Dependent service down |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limits

### Current Limits (No Enforcement)

**Integration Gateway**:
- No rate limit (development)
- Production: 1000 requests/hour per IP

**AI Services**:
- No rate limit (internal services)
- Production: Deploy behind API gateway

**External APIs**:
- **VirusTotal**: 500 requests/day (free tier)
- **AbuseIPDB**: 1000 requests/day (free tier)
- **Groq**: 30 requests/minute (free tier)

**Implement Rate Limiting** (Production):
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/webhook")
@limiter.limit("10/minute")
async def receive_webhook(...):
    ...
```

---

## API Examples

### Example 1: Send Alert and Trigger Investigation

```bash
# Step 1: Send alert to webhook
ALERT_ID=$(curl -s -X POST http://localhost:8002/webhook \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test-123",
    "rule": {"level": 12, "description": "Critical event"},
    "data": {"srcip": "192.168.1.100"}
  }' | jq -r '.alert_id')

# Step 2: Trigger investigation
curl -X POST http://localhost:8002/investigate/$ALERT_ID

# Step 3: Check PDF report
ls -l reports/IOC_Report_*.pdf
```

### Example 2: Complete Alert Enrichment Pipeline

```bash
# Get LLM triage
TRIAGE=$(curl -s -X POST http://localhost:8100/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "rule_description": "SSH brute force",
    "rule_level": 10,
    "source_ip": "192.168.1.100"
  }')

# Get MITRE context
MITRE=$(curl -s -X POST http://localhost:8001/retrieve \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SSH brute force",
    "top_k": 3
  }')

# Get ML prediction
ML=$(curl -s -X POST http://localhost:8500/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.0, ...],
    "model_name": "random_forest"
  }')

# Combine results
echo "Triage: $(echo $TRIAGE | jq -r '.severity')"
echo "MITRE: $(echo $MITRE | jq -r '.results[0].technique_id')"
echo "ML: $(echo $ML | jq -r '.prediction')"
```

### Example 3: Batch Processing

```bash
# Batch alert triage
curl -X POST http://localhost:8100/batch \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [
      {"alert_id": "001", "rule_level": 8, "source_ip": "10.0.0.1"},
      {"alert_id": "002", "rule_level": 12, "source_ip": "10.0.0.2"}
    ]
  }'
```

---

## OpenAPI / Swagger Documentation

All services expose interactive API documentation:

- **Integration Gateway**: http://localhost:8002/docs
- **Alert Triage**: http://localhost:8100/docs
- **RAG Service**: http://localhost:8001/docs
- **ML Inference**: http://localhost:8500/docs

**Try it out** directly in your browser!

---

## Client Libraries

### Python Client Example

```python
import requests

class CrewAIClient:
    def __init__(self, base_url="http://localhost:8002"):
        self.base_url = base_url
        self.api_key = "Apkl3@Jfyg2"
    
    def send_alert(self, alert: dict):
        response = requests.post(
            f"{self.base_url}/webhook",
            json=alert,
            headers={"X-API-Key": self.api_key}
        )
        return response.json()
    
    def investigate(self, alert_id: str):
        response = requests.post(
            f"{self.base_url}/investigate/{alert_id}"
        )
        return response.json()

# Usage
client = CrewAIClient()
result = client.send_alert({
    "rule": {"level": 10},
    "data": {"srcip": "192.168.1.100"}
})
```

---

**Last Updated**: 2026-01-20
=======
# API Reference
## Wazuh-CrewAI Threat Intelligence System

Complete API documentation for all services.

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Wazuh Integration Gateway API](#wazuh-integration-gateway-api)
4. [Alert Triage Service API](#alert-triage-service-api)
5. [RAG Service API](#rag-service-api)
6. [ML Inference Service API](#ml-inference-service-api)
7. [Error Handling](#error-handling)
8. [Rate Limits](#rate-limits)
9. [API Examples](#api-examples)

---

## Overview

### Base URLs

| Service | Base URL | Protocol |
|---------|----------|----------|
| **Wazuh Integration** | `http://localhost:8002` | HTTP |
| **Alert Triage** | `http://localhost:8100` | HTTP |
| **RAG Service** | `http://localhost:8001` | HTTP |
| **ML Inference** | `http://localhost:8500` | HTTP |

### Response Format

All APIs return JSON responses with the following structure:

**Success Response**:
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": "2026-01-20T17:34:56Z"
}
```

**Error Response**:
```json
{
  "status": "error",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid IP address format",
    "details": { ... }
  },
  "timestamp": "2026-01-20T17:34:56Z"
}
```

---

## Authentication

### Wazuh Integration Gateway

**API Key Authentication** (Header-based):

```bash
curl -X POST http://localhost:8002/webhook \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -H "Content-Type: application/json"
```

**Default API Key**: `Apkl3@Jfyg2` (Change in production!)

**Update API Key**:
Edit `.env` file:
```bash
WAZUH_INTEGRATION_API_KEY=your_secure_key_here
```

### Other Services

**No Authentication** (Internal services):
- Alert Triage Service
- RAG Service
- ML Inference Service

**Production**: Deploy behind reverse proxy with TLS + authentication.

---

## Wazuh Integration Gateway API

### POST /webhook

Receive and process Wazuh alerts.

**Endpoint**: `POST /webhook`

**Headers**:
```
Content-Type: application/json
X-API-Key: Apkl3@Jfyg2
```

**Request Body**:
```json
{
  "id": "1737389400.12345",
  "timestamp": "2026-01-20T12:30:00.000Z",
  "rule": {
    "level": 10,
    "description": "SSH brute force attack detected",
    "id": "5710",
    "groups": ["authentication_failed", "sshd"]
  },
  "data": {
    "srcip": "192.168.1.100",
    "dstip": "10.0.0.5",
    "srcport": 45678,
    "dstport": 22
  },
  "agent": {
    "id": "001",
    "name": "web-server-01"
  }
}
```

**Response** (Level < 6):
```json
{
  "status": "archived",
  "reason": "level < 6",
  "action": "none"
}
```

**Response** (Level 6-7):
```json
{
  "status": "dashboard_stored",
  "reason": "level 6-7",
  "action": "metrics_only"
}
```

**Response** (Level 8-9):
```json
{
  "status": "processed",
  "alert_id": "1737389400.12345",
  "rule_level": 8,
  "triage_severity": "high",
  "enrichments_applied": ["triage", "mitre", "ml"],
  "flagged_for_investigation": false
}
```

**Response** (Level 10+):
```json
{
  "status": "processed",
  "alert_id": "1737389400.12345",
  "rule_level": 12,
  "triage_severity": "critical",
  "enrichments_applied": ["triage", "mitre", "ml"],
  "flagged_for_investigation": true
}
```

**HTTP Status Codes**:
- `200 OK` - Alert processed successfully
- `401 Unauthorized` - Invalid API key
- `422 Unprocessable Entity` - Invalid alert format
- `500 Internal Server Error` - Processing error

---

### POST /investigate/{alert_id}

Trigger full CrewAI investigation for a specific alert.

**Endpoint**: `POST /investigate/{alert_id}`

**Parameters**:
- `alert_id` (path) - Alert identifier (e.g., "1737389400.12345")

**Headers**:
```
Content-Type: application/json
```

**Request Body**: None (alert_id in path)

**Example**:
```bash
curl -X POST http://localhost:8002/investigate/1737389400.12345
```

**Response**:
```json
{
  "status": "success",
  "alert_id": "1737389400.12345",
  "ip_address": "192.168.1.100",
  "pdf_report": "reports/IOC_Report_192_168_1_100_20260120_173456.pdf",
  "execution_time": "102.97s",
  "raw_result": "🔵 IOC Investigation Report\n**Target IP:** 192.168.1.100\n..."
}
```

**HTTP Status Codes**:
- `200 OK` - Investigation completed
- `404 Not Found` - Alert ID not found
- `400 Bad Request` - No source IP in alert
- `500 Internal Server Error` - Investigation failed

**Execution Time**: 90-120 seconds (all 10 agents)

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "wazuh-integration",
  "timestamp": "2026-01-20T17:34:56.084268"
}
```

**HTTP Status Codes**:
- `200 OK` - Service healthy
- `503 Service Unavailable` - Service unhealthy

---

### GET /metrics

Prometheus metrics endpoint.

**Endpoint**: `GET /metrics`

**Response** (Prometheus format):
```
# HELP wazuh_alerts_received_total Total alerts received from Wazuh
# TYPE wazuh_alerts_received_total counter
wazuh_alerts_received_total{severity="critical"} 15.0
wazuh_alerts_received_total{severity="high"} 42.0
wazuh_alerts_received_total{severity="medium"} 128.0

# HELP crewai_executions_total Total CrewAI agent executions
# TYPE crewai_executions_total counter
crewai_executions_total{status="success"} 8.0
crewai_executions_total{status="error"} 1.0

# HELP crewai_execution_duration_seconds Time spent executing CrewAI analysis
# TYPE crewai_execution_duration_seconds histogram
crewai_execution_duration_seconds_bucket{le="60.0"} 2.0
crewai_execution_duration_seconds_bucket{le="120.0"} 7.0
crewai_execution_duration_seconds_sum 856.32
crewai_execution_duration_seconds_count 8.0
```

---

## Alert Triage Service API

### POST /analyze

Analyze security alert using LLM.

**Endpoint**: `POST /analyze`

**Request Body**:
```json
{
  "alert_id": "test-001",
  "timestamp": "2026-01-20T12:00:00Z",
  "rule_id": "5710",
  "rule_description": "SSH brute force attack detected",
  "rule_level": 10,
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.5",
  "source_port": 45678,
  "dest_port": 22,
  "raw_log": "Failed password for root from 192.168.1.100 port 45678 ssh2"
}
```

**Response**:
```json
{
  "alert_id": "test-001",
  "severity": "high",
  "confidence": 0.92,
  "is_true_positive": true,
  "category": "intrusion_attempt",
  "summary": "SSH brute force attack detected from external IP. Multiple failed authentication attempts indicate credential guessing attack.",
  "iocs": [
    {
      "ioc_type": "ip",
      "value": "192.168.1.100",
      "confidence": 0.95
    },
    {
      "ioc_type": "port",
      "value": "22",
      "context": "SSH service targeted"
    }
  ],
  "mitre_techniques": [
    "T1110.001"
  ],
  "recommendations": [
    {
      "action": "Block source IP at firewall",
      "priority": 1,
      "rationale": "Prevent further brute force attempts"
    },
    {
      "action": "Review SSH logs for compromise indicators",
      "priority": 2,
      "rationale": "Check if any logins succeeded"
    },
    {
      "action": "Enable fail2ban if not configured",
      "priority": 3,
      "rationale": "Automated blocking of brute force attempts"
    }
  ],
  "model_used": "llama3.2:3b",
  "processing_time_ms": 2847
}
```

**HTTP Status Codes**:
- `200 OK` - Analysis completed
- `422 Unprocessable Entity` - Invalid request format
- `503 Service Unavailable` - LLM service unavailable

---

### POST /batch

Batch alert analysis (up to 100 alerts).

**Endpoint**: `POST /batch`

**Request Body**:
```json
{
  "alerts": [
    {
      "alert_id": "test-001",
      "rule_description": "SSH brute force",
      "rule_level": 10,
      "source_ip": "192.168.1.100"
    },
    {
      "alert_id": "test-002",
      "rule_description": "SQL injection attempt",
      "rule_level": 12,
      "source_ip": "203.0.113.42"
    }
  ]
}
```

**Response**:
```json
{
  "results": [
    {
      "alert_id": "test-001",
      "severity": "high",
      "confidence": 0.92
    },
    {
      "alert_id": "test-002",
      "severity": "critical",
      "confidence": 0.98
    }
  ],
  "total_processed": 2,
  "total_time_ms": 5632
}
```

**Limits**: Maximum 100 alerts per request

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "alert-triage",
  "llm_available": true,
  "model": "llama3.2:3b"
}
```

---

## RAG Service API

### POST /retrieve

Retrieve relevant MITRE ATT&CK techniques via semantic search.

**Endpoint**: `POST /retrieve`

**Request Body**:
```json
{
  "query": "SSH brute force credential guessing",
  "collection": "mitre_attack",
  "top_k": 5,
  "min_similarity": 0.3
}
```

**Response**:
```json
{
  "techniques_found": 5,
  "query_used": "SSH brute force credential guessing",
  "collection": "mitre_attack",
  "service_status": "available",
  "results": [
    {
      "technique_id": "T1110.001",
      "name": "Password Guessing",
      "tactic": "credential-access",
      "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained...",
      "similarity_score": 0.89,
      "platforms": ["Windows", "Linux", "macOS"],
      "detection": "Monitor authentication logs for system and application login failures of Valid Accounts...",
      "mitigation": "Refer to NIST guidelines when creating password policies..."
    },
    {
      "technique_id": "T1021.004",
      "name": "SSH",
      "tactic": "lateral-movement",
      "description": "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH)...",
      "similarity_score": 0.76,
      "platforms": ["Linux", "macOS"]
    }
  ]
}
```

**Parameters**:
- `query` (required) - Search query string
- `collection` (optional) - Collection name (default: "mitre_attack")
- `top_k` (optional) - Number of results (default: 5, max: 20)
- `min_similarity` (optional) - Minimum similarity threshold (default: 0.3)

**HTTP Status Codes**:
- `200 OK` - Retrieval successful
- `400 Bad Request` - Invalid query format
- `503 Service Unavailable` - ChromaDB unavailable

---

### POST /ingest

Ingest new documents into knowledge base (Admin only).

**Endpoint**: `POST /ingest`

**Request Body**:
```json
{
  "collection": "mitre_attack",
  "documents": [
    {
      "technique_id": "T1234",
      "name": "Custom Technique",
      "description": "Technique description...",
      "tactic": "execution",
      "platforms": ["Windows"]
    }
  ]
}
```

**Response**:
```json
{
  "status": "success",
  "documents_ingested": 1,
  "collection": "mitre_attack"
}
```

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "rag-service",
  "chromadb_available": true,
  "collections": ["mitre_attack"],
  "total_documents": 835
}
```

---

## ML Inference Service API

### POST /predict

Classify network traffic using ML models.

**Endpoint**: `POST /predict`

**Request Body**:
```json
{
  "features": [
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    // ... 77 total features
  ],
  "model_name": "random_forest"
}
```

**Feature Vector** (77 dimensions):
1. Flow Duration
2. Total Fwd Packets
3. Total Backward Packets
4. Total Length of Fwd Packets
5. Total Length of Bwd Packets
6. Fwd Packet Length Max
7. Fwd Packet Length Min
8. Fwd Packet Length Mean
9. Fwd Packet Length Std
10. Bwd Packet Length Max
... (see full list in model documentation)

**Response**:
```json
{
  "prediction": "BENIGN",
  "confidence": 0.86,
  "model_used": "random_forest",
  "probabilities": {
    "BENIGN": 0.86,
    "ATTACK": 0.14
  },
  "inference_time_ms": 3.2,
  "feature_count": 77
}
```

**Supported Models**:
- `random_forest` - RandomForest (99.28% accuracy)
- `xgboost` - XGBoost (99.21% accuracy)
- `decision_tree` - DecisionTree (99.10% accuracy)

**HTTP Status Codes**:
- `200 OK` - Prediction successful
- `422 Unprocessable Entity` - Invalid feature vector
- `503 Service Unavailable` - Model not loaded

---

### POST /batch_predict

Batch prediction (up to 1000 samples).

**Endpoint**: `POST /batch_predict`

**Request Body**:
```json
{
  "samples": [
    {
      "id": "flow-001",
      "features": [0.0, 0.0, ...]
    },
    {
      "id": "flow-002",
      "features": [0.0, 0.0, ...]
    }
  ],
  "model_name": "random_forest"
}
```

**Response**:
```json
{
  "predictions": [
    {
      "id": "flow-001",
      "prediction": "BENIGN",
      "confidence": 0.86
    },
    {
      "id": "flow-002",
      "prediction": "ATTACK",
      "confidence": 0.94
    }
  ],
  "total_samples": 2,
  "total_time_ms": 12.5
}
```

---

### GET /models

List available models.

**Endpoint**: `GET /models`

**Response**:
```json
{
  "models": [
    {
      "name": "random_forest",
      "accuracy": 0.9928,
      "loaded": true
    },
    {
      "name": "xgboost",
      "accuracy": 0.9921,
      "loaded": true
    },
    {
      "name": "decision_tree",
      "accuracy": 0.9910,
      "loaded": false
    }
  ]
}
```

---

### GET /health

Service health check.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "ml-inference",
  "models_loaded": 3,
  "default_model": "random_forest"
}
```

---

## Error Handling

### Standard Error Response

```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "specific_field",
      "reason": "validation_failed"
    }
  },
  "timestamp": "2026-01-20T17:34:56Z"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_API_KEY` | 401 | API key missing or invalid |
| `VALIDATION_ERROR` | 422 | Request validation failed |
| `NOT_FOUND` | 404 | Resource not found |
| `SERVICE_UNAVAILABLE` | 503 | Dependent service down |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limits

### Current Limits (No Enforcement)

**Integration Gateway**:
- No rate limit (development)
- Production: 1000 requests/hour per IP

**AI Services**:
- No rate limit (internal services)
- Production: Deploy behind API gateway

**External APIs**:
- **VirusTotal**: 500 requests/day (free tier)
- **AbuseIPDB**: 1000 requests/day (free tier)
- **Groq**: 30 requests/minute (free tier)

**Implement Rate Limiting** (Production):
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/webhook")
@limiter.limit("10/minute")
async def receive_webhook(...):
    ...
```

---

## API Examples

### Example 1: Send Alert and Trigger Investigation

```bash
# Step 1: Send alert to webhook
ALERT_ID=$(curl -s -X POST http://localhost:8002/webhook \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test-123",
    "rule": {"level": 12, "description": "Critical event"},
    "data": {"srcip": "192.168.1.100"}
  }' | jq -r '.alert_id')

# Step 2: Trigger investigation
curl -X POST http://localhost:8002/investigate/$ALERT_ID

# Step 3: Check PDF report
ls -l reports/IOC_Report_*.pdf
```

### Example 2: Complete Alert Enrichment Pipeline

```bash
# Get LLM triage
TRIAGE=$(curl -s -X POST http://localhost:8100/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "rule_description": "SSH brute force",
    "rule_level": 10,
    "source_ip": "192.168.1.100"
  }')

# Get MITRE context
MITRE=$(curl -s -X POST http://localhost:8001/retrieve \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SSH brute force",
    "top_k": 3
  }')

# Get ML prediction
ML=$(curl -s -X POST http://localhost:8500/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.0, ...],
    "model_name": "random_forest"
  }')

# Combine results
echo "Triage: $(echo $TRIAGE | jq -r '.severity')"
echo "MITRE: $(echo $MITRE | jq -r '.results[0].technique_id')"
echo "ML: $(echo $ML | jq -r '.prediction')"
```

### Example 3: Batch Processing

```bash
# Batch alert triage
curl -X POST http://localhost:8100/batch \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [
      {"alert_id": "001", "rule_level": 8, "source_ip": "10.0.0.1"},
      {"alert_id": "002", "rule_level": 12, "source_ip": "10.0.0.2"}
    ]
  }'
```

---

## OpenAPI / Swagger Documentation

All services expose interactive API documentation:

- **Integration Gateway**: http://localhost:8002/docs
- **Alert Triage**: http://localhost:8100/docs
- **RAG Service**: http://localhost:8001/docs
- **ML Inference**: http://localhost:8500/docs

**Try it out** directly in your browser!

---

## Client Libraries

### Python Client Example

```python
import requests

class CrewAIClient:
    def __init__(self, base_url="http://localhost:8002"):
        self.base_url = base_url
        self.api_key = "Apkl3@Jfyg2"
    
    def send_alert(self, alert: dict):
        response = requests.post(
            f"{self.base_url}/webhook",
            json=alert,
            headers={"X-API-Key": self.api_key}
        )
        return response.json()
    
    def investigate(self, alert_id: str):
        response = requests.post(
            f"{self.base_url}/investigate/{alert_id}"
        )
        return response.json()

# Usage
client = CrewAIClient()
result = client.send_alert({
    "rule": {"level": 10},
    "data": {"srcip": "192.168.1.100"}
})
```

---

**Last Updated**: 2026-01-20
>>>>>>> dev
**Next**: See [MONITORING.md](MONITORING.md) for observability setup