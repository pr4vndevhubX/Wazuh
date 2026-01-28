# Monitoring & Observability Guide
## Wazuh-CrewAI Threat Intelligence System

Complete monitoring, metrics, and logging configuration.

---

## Table of Contents

1. [Monitoring Stack Overview](#monitoring-stack-overview)
2. [Prometheus Configuration](#prometheus-configuration)
3. [Grafana Dashboards](#grafana-dashboards)
4. [Loki Log Aggregation](#loki-log-aggregation)
5. [AlertManager Setup](#alertmanager-setup)
6. [Service Instrumentation](#service-instrumentation)
7. [Custom Metrics](#custom-metrics)
8. [Troubleshooting Monitoring](#troubleshooting-monitoring)

---

## Monitoring Stack Overview

### Deployed Services

```
┌─────────────────────────────────────────────────────────┐
│              MONITORING ARCHITECTURE                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Prometheus (Port 9090)                          │  │
│  │  • Metrics collection                            │  │
│  │  • 15-second scrape interval                     │  │
│  │  • 30-day retention                              │  │
│  │  • PromQL query engine                           │  │
│  └────────────┬─────────────────────────────────────┘  │
│               ↓                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Grafana (Port 3000) - Optional                  │  │
│  │  • Visualization                                 │  │
│  │  • Pre-built dashboards                          │  │
│  │  • Alert management                              │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Loki (Port 3100)                                │  │
│  │  • Log aggregation                               │  │
│  │  • 7-day retention                               │  │
│  │  • Label-based indexing                          │  │
│  └────────────┬─────────────────────────────────────┘  │
│               ↑                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Promtail                                        │  │
│  │  • Log shipping                                  │  │
│  │  • Docker log collection                         │  │
│  │  • Label extraction                              │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Current Status

```bash
# Check monitoring services
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "prometheus|loki|promtail"
```

**Expected Output**:
```
prometheus      Up 3 hours      0.0.0.0:9090->9090/tcp
loki            Up 3 hours      0.0.0.0:3100->3100/tcp
promtail        Up 3 hours      (no ports)
```

---

## Prometheus Configuration

### Scrape Configuration

**File**: `config/prometheus/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s

scrape_configs:
  # Alert Triage Service
  - job_name: 'alert-triage'
    static_configs:
      - targets: ['host.docker.internal:8100']
    metrics_path: '/metrics'
    
  # RAG Service
  - job_name: 'rag-service'
    static_configs:
      - targets: ['host.docker.internal:8001']
    metrics_path: '/metrics'
    
  # ML Inference Service
  - job_name: 'ml-inference'
    static_configs:
      - targets: ['host.docker.internal:8500']
    metrics_path: '/metrics'
    
  # Wazuh Integration Gateway
  - job_name: 'wazuh-integration'
    static_configs:
      - targets: ['host.docker.internal:8002']
    metrics_path: '/metrics'
    
  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### Viewing Targets

```bash
# Access Prometheus UI
open http://localhost:9090

# Or via CLI
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
```

**Expected Output**:
```json
{"job": "alert-triage", "health": "up"}
{"job": "rag-service", "health": "up"}
{"job": "ml-inference", "health": "up"}
{"job": "wazuh-integration", "health": "up"}
```

### Useful PromQL Queries

**Alert Volume**:
```promql
# Total alerts received per minute
rate(wazuh_alerts_received_total[1m])

# Alerts by severity
sum by (severity) (wazuh_alerts_received_total)
```

**CrewAI Performance**:
```promql
# Average investigation duration
avg(crewai_execution_duration_seconds)

# 95th percentile duration
histogram_quantile(0.95, crewai_execution_duration_seconds_bucket)

# Success rate
sum(crewai_executions_total{status="success"}) / sum(crewai_executions_total)
```

**Service Health**:
```promql
# Service uptime
up{job="alert-triage"}

# All services up
count(up == 1)

# Services down
count(up == 0)
```

**ML Inference Metrics**:
```promql
# Predictions per second
rate(ml_predictions_total[1m])

# Average inference latency
rate(ml_inference_duration_seconds_sum[1m]) / rate(ml_inference_duration_seconds_count[1m])
```

---

## Grafana Dashboards

### Access Grafana

**If deployed separately**:
```bash
docker run -d \
  --name=grafana \
  -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=admin123 \
  grafana/grafana:latest
```

**URL**: http://localhost:3000
**Login**: `admin` / `admin123`

### Add Prometheus Datasource

1. Navigate to **Configuration → Data Sources**
2. Click **Add data source**
3. Select **Prometheus**
4. Configure:
   - **URL**: `http://prometheus:9090` (Docker) or `http://localhost:9090` (host)
   - **Access**: Server (default)
5. Click **Save & Test**

### Pre-Built Dashboards

#### Dashboard 1: System Overview

**Panels**:
- Service health status (gauge)
- Alerts received per minute (graph)
- CrewAI investigations (counter)
- System resource usage (graph)

**Import JSON**:
```bash
# Copy dashboard JSON
cp config/grafana/dashboards/system-overview.json /path/to/grafana/provisioning/dashboards/
```

#### Dashboard 2: Alert Processing

**Panels**:
- Alert severity distribution (pie chart)
- Triage service latency (graph)
- ML inference accuracy (gauge)
- RAG retrieval performance (graph)

#### Dashboard 3: CrewAI Performance

**Panels**:
- Investigation duration (histogram)
- Agent execution times (stacked bar)
- Success/failure rate (gauge)
- PDF reports generated (counter)

### Create Custom Dashboard

```bash
# Access Grafana UI
open http://localhost:3000

# Steps:
# 1. Click "+" → Dashboard
# 2. Add panel → Select Prometheus datasource
# 3. Enter PromQL query
# 4. Configure visualization
# 5. Save dashboard
```

**Example Panel**:
- **Query**: `rate(wazuh_alerts_received_total{severity="critical"}[5m])`
- **Visualization**: Time series
- **Title**: "Critical Alerts per Minute"

---

## Loki Log Aggregation

### Loki Configuration

**File**: `config/loki/loki-config.yaml`

```yaml
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/index
    cache_location: /loki/index_cache
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

limits_config:
  retention_period: 168h  # 7 days
```

### Promtail Configuration

**File**: `config/promtail/promtail-config.yaml`

```yaml
server:
  http_listen_port: 9080

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  # Docker containers
  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
    relabel_configs:
      - source_labels: [__meta_docker_container_name]
        target_label: container
      - source_labels: [__meta_docker_container_log_stream]
        target_label: stream
```

### Querying Logs

**Using LogCLI**:
```bash
# Install logcli
brew install logcli  # macOS
# or
curl -O -L "https://github.com/grafana/loki/releases/latest/download/logcli-linux-amd64.zip"

# Configure endpoint
export LOKI_ADDR=http://localhost:3100

# Query logs
logcli query '{container_name="alert-triage"}'

# Filter by error
logcli query '{container_name="alert-triage"} |= "error"'

# Time range
logcli query --since=1h '{container_name="alert-triage"}'
```

**Using Grafana Explore**:
1. Navigate to **Explore** (compass icon)
2. Select **Loki** datasource
3. Enter LogQL query:
   ```
   {container_name="alert-triage"} |= "error"
   ```
4. Click **Run Query**

### Useful LogQL Queries

```logql
# All logs from alert-triage
{container_name="alert-triage"}

# Errors across all services
{container_name=~"alert-triage|rag-service|ml-inference"} |= "error"

# Investigation completions
{container_name="wazuh-integration"} |= "Investigation completed"

# Rate of errors
rate({container_name="alert-triage"} |= "error" [5m])

# Count by severity
sum by (severity) (count_over_time({container_name="alert-triage"} | json | __error__="" [5m]))
```

---

## AlertManager Setup

### Configuration

**File**: `config/alertmanager/alertmanager.yml`

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      repeat_interval: 30m
    
    - match:
        severity: warning
      receiver: 'warning-alerts'
      repeat_interval: 4h

receivers:
  - name: 'default'
    webhook_configs:
      - url: 'http://localhost:8002/alertmanager-webhook'
  
  - name: 'critical-alerts'
    email_configs:
      - to: 'security-team@example.com'
        from: 'alerts@example.com'
        smarthost: 'smtp.gmail.com:587'
        auth_username: 'alerts@example.com'
        auth_password: 'your-app-password'
    
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#security-alerts'
        title: '🚨 CRITICAL ALERT'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
  
  - name: 'warning-alerts'
    email_configs:
      - to: 'ops-team@example.com'
        from: 'alerts@example.com'
```

### Alert Rules

**File**: `config/prometheus/alerts/ai-soc-alerts.yml`

```yaml
groups:
  - name: siem_alerts
    interval: 30s
    rules:
      - alert: HighAlertRate
        expr: rate(wazuh_alerts_received_total[5m]) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High alert rate detected"
          description: "Alert rate is {{ $value }} alerts/min"
      
      - alert: NoEventsProcessed
        expr: rate(wazuh_alerts_received_total[5m]) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No events being processed"
          description: "Wazuh stopped sending alerts"
  
  - name: crewai_alerts
    interval: 30s
    rules:
      - alert: CrewAIInvestigationFailed
        expr: rate(crewai_executions_total{status="error"}[5m]) > 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "CrewAI investigation failed"
          description: "{{ $value }} failures in last 5 minutes"
      
      - alert: CrewAIHighLatency
        expr: histogram_quantile(0.95, crewai_execution_duration_seconds_bucket) > 180
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "CrewAI investigations slow"
          description: "P95 latency is {{ $value }}s (threshold: 180s)"
  
  - name: service_health
    interval: 30s
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} is down"
          description: "Service has been down for 2 minutes"
```

### Test Alerts

```bash
# Check alert rules loaded
curl http://localhost:9090/api/v1/rules | jq '.data.groups[].rules[] | {alert: .name, state: .state}'

# Fire test alert
curl -X POST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{
    "labels": {"alertname": "Test", "severity": "warning"},
    "annotations": {"description": "Test alert"}
  }]'

# Check AlertManager
curl http://localhost:9093/api/v2/alerts | jq
```

---

## Service Instrumentation

### Adding Metrics to Python Services

**Install Prometheus client**:
```bash
pip install prometheus-client
```

**Example instrumentation**:

```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import FastAPI, Response

app = FastAPI()

# Define metrics
requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

active_requests = Gauge(
    'http_requests_active',
    'Active HTTP requests'
)

# Middleware
@app.middleware("http")
async def prometheus_middleware(request, call_next):
    active_requests.inc()
    
    with request_duration.labels(
        method=request.method,
        endpoint=request.url.path
    ).time():
        response = await call_next(request)
    
    requests_total.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    active_requests.dec()
    return response

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type="text/plain")
```

### Custom Metrics for CrewAI

```python
from prometheus_client import Counter, Histogram

# CrewAI-specific metrics
crewai_executions = Counter(
    'crewai_executions_total',
    'Total CrewAI executions',
    ['status']
)

crewai_duration = Histogram(
    'crewai_execution_duration_seconds',
    'CrewAI execution duration',
    buckets=[30, 60, 90, 120, 180, 300]
)

# Usage
start_time = time.time()
try:
    result = crew.kickoff(inputs={'ip_address': ip})
    crewai_executions.labels(status='success').inc()
except Exception as e:
    crewai_executions.labels(status='error').inc()
finally:
    crewai_duration.observe(time.time() - start_time)
```

---

## Custom Metrics

### Alert Processing Metrics

```python
# Wazuh Integration Gateway
from prometheus_client import Counter

alerts_received = Counter(
    'wazuh_alerts_received_total',
    'Total alerts received',
    ['severity']
)

alerts_filtered = Counter(
    'alerts_filtered_total',
    'Alerts filtered out',
    ['reason']
)

# Usage
if rule_level < 6:
    alerts_filtered.labels(reason='low_severity').inc()
elif rule_level >= 8:
    alerts_received.labels(severity='high').inc()
```

### ML Inference Metrics

```python
ml_predictions = Counter(
    'ml_predictions_total',
    'Total ML predictions',
    ['model', 'prediction']
)

ml_inference_duration = Histogram(
    'ml_inference_duration_seconds',
    'ML inference duration',
    ['model']
)

# Usage
with ml_inference_duration.labels(model='random_forest').time():
    prediction = model.predict(features)
    ml_predictions.labels(
        model='random_forest',
        prediction=prediction
    ).inc()
```

---

## Troubleshooting Monitoring

### Issue: Prometheus Not Scraping Targets

**Check target configuration**:
```bash
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up")'
```

**Common fixes**:
```bash
# 1. Service not exposing /metrics
curl http://localhost:8100/metrics

# 2. Wrong port in prometheus.yml
grep -A3 "alert-triage" config/prometheus/prometheus.yml

# 3. Firewall blocking
sudo ufw status | grep 8100
```

### Issue: Grafana Can't Connect to Prometheus

**Test connection**:
```bash
# From Grafana container
docker exec -it grafana curl http://prometheus:9090/api/v1/query?query=up
```

**Fix**:
- Update datasource URL to `http://prometheus:9090`
- Ensure both containers on same network

### Issue: Loki Not Receiving Logs

**Check Promtail**:
```bash
docker logs promtail | grep -i error

# Check Promtail positions
docker exec promtail cat /tmp/positions.yaml
```

**Test Loki**:
```bash
curl http://localhost:3100/ready
curl http://localhost:3100/metrics
```

### Issue: High Cardinality Metrics

**Symptom**: Prometheus memory usage high

**Solution**: Reduce label cardinality
```python
# BAD: Too many unique labels
requests.labels(
    user_id=user_id,  # High cardinality
    ip_address=ip     # High cardinality
).inc()

# GOOD: Group by category
requests.labels(
    user_type='authenticated',
    ip_class='internal'
).inc()
```

---

## Monitoring Best Practices

1. **Keep labels low cardinality** (< 10 unique values)
2. **Use histograms for latency** (not gauges)
3. **Set appropriate retention** (balance storage vs history)
4. **Alert on symptoms, not causes** (e.g., "high latency" not "CPU usage")
5. **Test alerts regularly** (fire test alerts monthly)
6. **Document runbooks** (what to do when alert fires)

---

**Last Updated**: 2026-01-20
**Next**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues