# Wazuh-CrewAI Quick Start Guide

Get your AI-powered threat intelligence system running in **5 minutes**.

---

## Prerequisites Check

Before starting, verify you have:

```bash
# Check Docker
docker --version
# Required: 24.0+

# Check Docker Compose
docker-compose --version
# Required: 2.20+

# Check available memory
free -h
# Required: 16GB minimum

# Check disk space
df -h
# Required: 50GB available
```

---

## Step 1: Clone Repository

```bash
git clone <your-repository-url>
cd Threat-Intelligence-with-SIEM
```

---

## Step 2: Configure Environment

### Copy Environment Template

```bash
cp .env.example .env
```

### Required API Keys

Edit `.env` and add these **mandatory** keys:

```bash
# External Threat Intelligence
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# LLM Provider (Groq)
OPENROUTER_API_KEY=your_groq_key_here
OPENROUTER_MODEL=llama-3.3-70b-versatile
OPENROUTER_API_BASE=https://api.groq.com/openai/v1

# YETI Platform (Optional)
YETI_URL=http://192.168.217.128:8000
YETI_USERNAME=admin
YETI_PASSWORD=your_password
```

### Get Free API Keys

- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **Groq**: https://console.groq.com/keys (Free tier available)

---

## Step 3: Fix Port Configuration ⚠️

Your services are on **non-standard ports**. Update `main-wazuh-integration.py`:

```python
# Line 28-30 - Change these:
RAG_SERVICE_URL = "http://localhost:8001/retrieve"    # Was 8200
ML_SERVICE_URL = "http://localhost:8500/predict"      # Was 8300
```

Save the file after editing.

---

## Step 4: Start All Services

```bash
# Start monitoring stack
docker-compose -f docker-compose/monitoring-stack.yml up -d

# Start AI services (already running in your case)
docker-compose -f docker-compose/ai-services.yml up -d

# Start integration gateway
cd services/wazuh-integration
python main.py
```

### Verify All Services Running

```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

**Expected output**:
```
NAMES           STATUS              PORTS
alert-triage    Up (healthy)        0.0.0.0:8100->8000/tcp
rag-service     Up (healthy)        0.0.0.0:8001->8000/tcp
ids-inference   Up (healthy)        0.0.0.0:8500->8000/tcp
prometheus      Up                  0.0.0.0:9090->9090/tcp
loki            Up                  0.0.0.0:3100->3100/tcp
chromadb        Up                  0.0.0.0:8000->8000/tcp
ollama          Up                  11434/tcp
promtail        Up
```

---

## Step 5: Health Check

Test each service is responding:

```bash
# Integration Gateway
curl http://localhost:8002/health

# Alert Triage
curl http://localhost:8100/health

# RAG Service
curl http://localhost:8001/health

# ML Inference
curl http://localhost:8500/health

# Prometheus
curl http://localhost:9090/-/healthy

# Loki
curl http://localhost:3100/ready
```

**All should return**: `{"status": "healthy"}` or `200 OK`

---

## Step 6: Run Your First Investigation

### Test Alert Routing

```bash
# Send a test alert (Level 8 - triggers triage)
curl -X POST http://localhost:8002/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -d '{
    "id": "test-001",
    "timestamp": "2026-01-20T12:00:00Z",
    "rule": {
      "level": 8,
      "description": "SSH brute force detected",
      "id": "5710"
    },
    "data": {
      "srcip": "192.168.1.100",
      "dstip": "10.0.0.5"
    }
  }'
```

**Expected Response**:
```json
{
  "status": "processed",
  "alert_id": "test-001",
  "rule_level": 8,
  "triage_severity": "high",
  "enrichments_applied": ["triage", "mitre", "ml"]
}
```

### Trigger Full CrewAI Investigation

```bash
# This runs all 10 agents (takes 90-120 seconds)
curl -X POST http://localhost:8002/investigate/test-001
```

**Wait for completion**, then check:

```bash
# View generated PDF report
ls -lh reports/IOC_Report_*.pdf

# Example output:
# -rw-r--r-- 1 user user 245K Jan 20 17:34 IOC_Report_192_168_1_100_20260120_173424.pdf
```

---

## Step 7: Access Monitoring Dashboards

### Prometheus (Metrics)

**URL**: http://localhost:9090

**Try these queries**:
```
# Total alerts received
wazuh_alerts_received_total

# CrewAI execution duration
crewai_execution_duration_seconds

# Service health
up{job="alert-triage"}
```

### Grafana (Visualization)

**If deployed separately**:
- URL: http://localhost:3000
- Username: `admin`
- Password: Check your `.env` file

---

## What Just Happened?

You deployed a complete AI-powered SOC with:

1. **8 Microservices**:
   - Alert Triage (LLM analysis)
   - RAG Service (MITRE ATT&CK)
   - ML Inference (Network classification)
   - ChromaDB (Vector database)
   - Ollama (Local LLM)
   - Prometheus (Metrics)
   - Loki (Logs)
   - Promtail (Log shipper)

2. **10 CrewAI Agents**:
   - Coordinator, VirusTotal, AbuseIPDB, YETI, SIEM
   - ML Classifier, Alert Triage, MITRE Context
   - Correlation Analyst, Report Generator

3. **Complete Investigation Pipeline**:
   - Automatic alert enrichment (Level 8+)
   - On-demand deep investigation
   - PDF report generation

---

## Common First-Run Issues

### Issue: Service Not Healthy

```bash
# Check logs
docker logs alert-triage

# Restart service
docker-compose -f docker-compose/ai-services.yml restart alert-triage
```

### Issue: Port Already in Use

```bash
# Find what's using the port
sudo lsof -i :8100

# Kill the process or change port in docker-compose.yml
```

### Issue: API Keys Invalid

```bash
# Verify keys are set
grep VIRUSTOTAL_API_KEY .env
grep ABUSEIPDB_API_KEY .env
grep OPENROUTER_API_KEY .env

# Re-test with valid keys
```

### Issue: Out of Memory

```bash
# Check Docker memory limit
docker system df

# Increase Docker Desktop memory to 16GB+
# Settings → Resources → Memory → 16GB
```

---

## Next Steps

Now that your system is running:

### 1. Deploy Wazuh SIEM

```bash
# Follow INSTALLATION.md for full Wazuh deployment
# This adds the alert source
```

### 2. Configure Wazuh Webhook

Add to Wazuh Manager config (`ossec.conf`):

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://192.168.217.122:8002/webhook</hook_url>
  <level>8</level>
  <alert_format>json</alert_format>
</integration>
```

### 3. Build SOC Dashboard

Create a web UI with:
- Alert list view
- "Investigate" button
- PDF report viewer
- Metrics visualization

### 4. Customize Agent Behavior

Edit `config/agents.yaml` and `config/tasks.yaml` to:
- Adjust agent personalities
- Change task descriptions
- Add new agents
- Modify workflow

---

## Stopping Services

```bash
# Stop integration gateway
# Ctrl+C in the terminal running main.py

# Stop AI services
docker-compose -f docker-compose/ai-services.yml down

# Stop monitoring
docker-compose -f docker-compose/monitoring-stack.yml down

# Stop everything
docker-compose down
```

---

## Getting Help

**Documentation**:
- [README.md](README.md) - Full project overview
- [INSTALLATION.md](INSTALLATION.md) - Detailed setup
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues

**Logs**:
```bash
# View service logs
docker logs -f alert-triage
docker logs -f rag-service
docker logs -f ids-inference

# View all logs
docker-compose logs -f
```

**Health Checks**:
```bash
# Run comprehensive test
python test/test_wazuh_integration.py
python test/test_crewai_investigation.py
```

---

## Congratulations! 🎉

Your AI-powered threat intelligence system is now operational.

**What you can do now**:
- ✅ Receive Wazuh alerts (once integrated)
- ✅ Automatic LLM triage (Level 8+)
- ✅ On-demand deep investigation
- ✅ PDF report generation
- ✅ Real-time monitoring

**Next**: Read [INSTALLATION.md](INSTALLATION.md) for Wazuh integration and production deployment.

---

**Need more help?** Open an issue on GitHub or contact the maintainer.

=======
# Wazuh-CrewAI Quick Start Guide

Get your AI-powered threat intelligence system running in **5 minutes**.

---

## Prerequisites Check

Before starting, verify you have:

```bash
# Check Docker
docker --version
# Required: 24.0+

# Check Docker Compose
docker-compose --version
# Required: 2.20+

# Check available memory
free -h
# Required: 16GB minimum

# Check disk space
df -h
# Required: 50GB available
```

---

## Step 1: Clone Repository

```bash
git clone <your-repository-url>
cd Threat-Intelligence-with-SIEM
```

---

## Step 2: Configure Environment

### Copy Environment Template

```bash
cp .env.example .env
```

### Required API Keys

Edit `.env` and add these **mandatory** keys:

```bash
# External Threat Intelligence
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# LLM Provider (Groq)
OPENROUTER_API_KEY=your_groq_key_here
OPENROUTER_MODEL=llama-3.3-70b-versatile
OPENROUTER_API_BASE=https://api.groq.com/openai/v1

# YETI Platform (Optional)
YETI_URL=http://192.168.217.128:8000
YETI_USERNAME=admin
YETI_PASSWORD=your_password
```

### Get Free API Keys

- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **Groq**: https://console.groq.com/keys (Free tier available)

---

## Step 3: Fix Port Configuration ⚠️

Your services are on **non-standard ports**. Update `main-wazuh-integration.py`:

```python
# Line 28-30 - Change these:
RAG_SERVICE_URL = "http://localhost:8001/retrieve"    # Was 8200
ML_SERVICE_URL = "http://localhost:8500/predict"      # Was 8300
```

Save the file after editing.

---

## Step 4: Start All Services

```bash
# Start monitoring stack
docker-compose -f docker-compose/monitoring-stack.yml up -d

# Start AI services (already running in your case)
docker-compose -f docker-compose/ai-services.yml up -d

# Start integration gateway
cd services/wazuh-integration
python main.py
```

### Verify All Services Running

```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

**Expected output**:
```
NAMES           STATUS              PORTS
alert-triage    Up (healthy)        0.0.0.0:8100->8000/tcp
rag-service     Up (healthy)        0.0.0.0:8001->8000/tcp
ids-inference   Up (healthy)        0.0.0.0:8500->8000/tcp
prometheus      Up                  0.0.0.0:9090->9090/tcp
loki            Up                  0.0.0.0:3100->3100/tcp
chromadb        Up                  0.0.0.0:8000->8000/tcp
ollama          Up                  11434/tcp
promtail        Up
```

---

## Step 5: Health Check

Test each service is responding:

```bash
# Integration Gateway
curl http://localhost:8002/health

# Alert Triage
curl http://localhost:8100/health

# RAG Service
curl http://localhost:8001/health

# ML Inference
curl http://localhost:8500/health

# Prometheus
curl http://localhost:9090/-/healthy

# Loki
curl http://localhost:3100/ready
```

**All should return**: `{"status": "healthy"}` or `200 OK`

---

## Step 6: Run Your First Investigation

### Test Alert Routing

```bash
# Send a test alert (Level 8 - triggers triage)
curl -X POST http://localhost:8002/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -d '{
    "id": "test-001",
    "timestamp": "2026-01-20T12:00:00Z",
    "rule": {
      "level": 8,
      "description": "SSH brute force detected",
      "id": "5710"
    },
    "data": {
      "srcip": "192.168.1.100",
      "dstip": "10.0.0.5"
    }
  }'
```

**Expected Response**:
```json
{
  "status": "processed",
  "alert_id": "test-001",
  "rule_level": 8,
  "triage_severity": "high",
  "enrichments_applied": ["triage", "mitre", "ml"]
}
```

### Trigger Full CrewAI Investigation

```bash
# This runs all 10 agents (takes 90-120 seconds)
curl -X POST http://localhost:8002/investigate/test-001
```

**Wait for completion**, then check:

```bash
# View generated PDF report
ls -lh reports/IOC_Report_*.pdf

# Example output:
# -rw-r--r-- 1 user user 245K Jan 20 17:34 IOC_Report_192_168_1_100_20260120_173424.pdf
```

---

## Step 7: Access Monitoring Dashboards

### Prometheus (Metrics)

**URL**: http://localhost:9090

**Try these queries**:
```
# Total alerts received
wazuh_alerts_received_total

# CrewAI execution duration
crewai_execution_duration_seconds

# Service health
up{job="alert-triage"}
```

### Grafana (Visualization)

**If deployed separately**:
- URL: http://localhost:3000
- Username: `admin`
- Password: Check your `.env` file

---

## What Just Happened?

You deployed a complete AI-powered SOC with:

1. **8 Microservices**:
   - Alert Triage (LLM analysis)
   - RAG Service (MITRE ATT&CK)
   - ML Inference (Network classification)
   - ChromaDB (Vector database)
   - Ollama (Local LLM)
   - Prometheus (Metrics)
   - Loki (Logs)
   - Promtail (Log shipper)

2. **10 CrewAI Agents**:
   - Coordinator, VirusTotal, AbuseIPDB, YETI, SIEM
   - ML Classifier, Alert Triage, MITRE Context
   - Correlation Analyst, Report Generator

3. **Complete Investigation Pipeline**:
   - Automatic alert enrichment (Level 8+)
   - On-demand deep investigation
   - PDF report generation

---

## Common First-Run Issues

### Issue: Service Not Healthy

```bash
# Check logs
docker logs alert-triage

# Restart service
docker-compose -f docker-compose/ai-services.yml restart alert-triage
```

### Issue: Port Already in Use

```bash
# Find what's using the port
sudo lsof -i :8100

# Kill the process or change port in docker-compose.yml
```

### Issue: API Keys Invalid

```bash
# Verify keys are set
grep VIRUSTOTAL_API_KEY .env
grep ABUSEIPDB_API_KEY .env
grep OPENROUTER_API_KEY .env

# Re-test with valid keys
```

### Issue: Out of Memory

```bash
# Check Docker memory limit
docker system df

# Increase Docker Desktop memory to 16GB+
# Settings → Resources → Memory → 16GB
```

---

## Next Steps

Now that your system is running:

### 1. Deploy Wazuh SIEM

```bash
# Follow INSTALLATION.md for full Wazuh deployment
# This adds the alert source
```

### 2. Configure Wazuh Webhook

Add to Wazuh Manager config (`ossec.conf`):

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://192.168.217.122:8002/webhook</hook_url>
  <level>8</level>
  <alert_format>json</alert_format>
</integration>
```

### 3. Build SOC Dashboard

Create a web UI with:
- Alert list view
- "Investigate" button
- PDF report viewer
- Metrics visualization

### 4. Customize Agent Behavior

Edit `config/agents.yaml` and `config/tasks.yaml` to:
- Adjust agent personalities
- Change task descriptions
- Add new agents
- Modify workflow

---

## Stopping Services

```bash
# Stop integration gateway
# Ctrl+C in the terminal running main.py

# Stop AI services
docker-compose -f docker-compose/ai-services.yml down

# Stop monitoring
docker-compose -f docker-compose/monitoring-stack.yml down

# Stop everything
docker-compose down
```

---

## Getting Help

**Documentation**:
- [README.md](README.md) - Full project overview
- [INSTALLATION.md](INSTALLATION.md) - Detailed setup
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues

**Logs**:
```bash
# View service logs
docker logs -f alert-triage
docker logs -f rag-service
docker logs -f ids-inference

# View all logs
docker-compose logs -f
```

**Health Checks**:
```bash
# Run comprehensive test
python test/test_wazuh_integration.py
python test/test_crewai_investigation.py
```

---

## Congratulations! 🎉

Your AI-powered threat intelligence system is now operational.

**What you can do now**:
- ✅ Receive Wazuh alerts (once integrated)
- ✅ Automatic LLM triage (Level 8+)
- ✅ On-demand deep investigation
- ✅ PDF report generation
- ✅ Real-time monitoring

**Next**: Read [INSTALLATION.md](INSTALLATION.md) for Wazuh integration and production deployment.

---

**Need more help?** Open an issue on GitHub or contact the maintainer.

>>>>>>> dev
**Last Updated**: 2026-01-20