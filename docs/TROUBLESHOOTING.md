# Troubleshooting Guide
## Wazuh-CrewAI Threat Intelligence System

Common issues and their solutions.

---

## Quick Diagnosis

### System Health Check

```bash
# Check all services
sudo docker ps --format "table {{.Names}}\t{{.Status}}"

# Check service health
curl http://localhost:8002/health  # Integration Gateway
curl http://localhost:8100/health  # Alert Triage
curl http://localhost:8001/health  # RAG Service
curl http://localhost:8500/health  # ML Inference

# Check logs
docker logs alert-triage --tail 50
docker logs rag-service --tail 50
docker logs ids-inference --tail 50
```

---

## Service Won't Start

### Issue: Docker Container Exits Immediately

**Diagnosis**:
```bash
docker logs <container_name>
```

**Common Causes**:

1. **Missing Environment Variables**
```bash
# Check .env file exists
ls -la .env

# Verify API keys set
grep VIRUSTOTAL_API_KEY .env
```

**Fix**: Copy `.env.example` to `.env` and add API keys

2. **Port Already in Use**
```bash
sudo lsof -i :8100
```

**Fix**: Kill process or change port in docker-compose.yml

3. **Insufficient Memory**
```bash
docker stats
```

**Fix**: Increase Docker memory to 16GB+

---

## Port Configuration Issues

### Issue: Services on Wrong Ports

**Your deployment**:
- RAG Service: Port 8001 (should be 8200)
- ML Inference: Port 8500 (should be 8300)

**Fix**: Update `main-wazuh-integration.py`:

```python
# Line 28-30
RAG_SERVICE_URL = "http://localhost:8001/retrieve"    # NOT 8200
ML_SERVICE_URL = "http://localhost:8500/predict"      # NOT 8300
```

Restart integration service after change.

---

## CrewAI Investigation Fails

### Issue: Investigation Times Out or Errors

**Diagnosis**:
```bash
python test/test_crewai_investigation.py
```

**Common Causes**:

1. **External API Keys Invalid**
```python
# Test VirusTotal
curl https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8 \
  -H "x-apikey: YOUR_KEY"

# Test AbuseIPDB
curl https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8 \
  -H "Key: YOUR_KEY"
```

**Fix**: Get valid API keys and update `.env`

2. **YETI Authentication Failed**
```bash
# Check YETI credentials
grep YETI_ .env

# Test YETI connection
curl -X POST http://192.168.217.128:8000/api/v2/auth/token \
  -d "username=admin&password=your_password"
```

**Fix**: Update YETI_PASSWORD in `.env` or disable YETI tool

3. **Groq API Rate Limit**
```
INFO:httpx:HTTP Request: POST https://api.groq.com/openai/v1/chat/completions "HTTP/1.1 429 Too Many Requests"
```

**Fix**: Wait 1 minute or upgrade Groq plan

---

## Microservice Connection Issues

### Issue: Integration Gateway Can't Reach Services

**Error**: `Cannot connect to http://localhost:8100`

**Diagnosis**:
```bash
# Test from host
curl http://localhost:8100/health

# Check Docker network
docker network ls
docker network inspect monitoring
```

**Fix**:

If running integration gateway **outside Docker**, use:
```python
ALERT_TRIAGE_URL = "http://localhost:8100/analyze"
RAG_SERVICE_URL = "http://localhost:8001/retrieve"
ML_SERVICE_URL = "http://localhost:8500/predict"
```

If running integration gateway **inside Docker**, use:
```python
ALERT_TRIAGE_URL = "http://alert-triage:8000/analyze"
RAG_SERVICE_URL = "http://rag-service:8000/retrieve"
ML_SERVICE_URL = "http://ids-inference:8000/predict"
```

---

## Database & Storage Issues

### Issue: ChromaDB Connection Failed

**Error**: `chromadb.errors.ChromaClientException: Could not connect to tenant default_tenant`

**Fix**:
```bash
# Restart ChromaDB
docker restart chromadb

# Wait 30 seconds
sleep 30

# Test connection
curl http://localhost:8000/api/v1/heartbeat
```

### Issue: Ollama Model Not Loaded

**Error**: `Model llama3.2:3b not found`

**Fix**:
```bash
# List models
docker exec ollama ollama list

# Pull model if missing
docker exec ollama ollama pull llama3.2:3b

# Verify
docker exec ollama ollama run llama3.2:3b "test"
```

---

## PDF Report Generation Fails

### Issue: No PDF Generated

**Diagnosis**:
```bash
ls -lh reports/
```

**Common Causes**:

1. **Missing reportlab library**
```bash
pip install reportlab
```

2. **Write permissions**
```bash
chmod 777 reports/
```

3. **Investigation didn't complete**
```bash
# Check logs
docker logs wazuh-integration | grep "Investigation completed"
```

---

## Performance Issues

### Issue: Slow Investigation (>180 seconds)

**Expected**: 90-120 seconds
**Yours**: >180 seconds

**Diagnosis**:
```bash
# Check which agent is slow
docker logs wazuh-integration | grep "Agent:"
```

**Common Bottlenecks**:

1. **Groq API Latency** - Rate limits or slow responses
2. **External API Timeouts** - VirusTotal/AbuseIPDB slow
3. **YETI Failure** - Waiting for timeout on failed auth

**Fix**: Disable slow/failing tools temporarily:

```python
# In agents.yaml, comment out problematic agents
# coordinator_agent:
#   role: ...

# Or increase timeouts in tools/
```

---

## Monitoring Issues

### Issue: Prometheus Not Scraping

**Diagnosis**:
```bash
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
```

**Fix**:
```bash
# 1. Check service exposes /metrics
curl http://localhost:8100/metrics

# 2. Update prometheus.yml if needed
nano config/prometheus/prometheus.yml

# 3. Reload Prometheus
docker exec prometheus kill -HUP 1
```

### Issue: Loki Not Receiving Logs

**Fix**:
```bash
# Restart Promtail
docker restart promtail

# Check Promtail logs
docker logs promtail | grep -i error

# Test Loki
curl http://localhost:3100/ready
```

---

## Memory / Resource Issues

### Issue: Out of Memory

**Symptoms**:
- Docker containers killed (OOM)
- System freeze
- Services crash randomly

**Diagnosis**:
```bash
docker stats
free -h
```

**Fix**:

1. **Increase Docker memory** (Docker Desktop → Settings → Resources)
2. **Add resource limits** to docker-compose.yml:
```yaml
services:
  alert-triage:
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 2G
```

3. **Stop unused services**:
```bash
docker-compose down
docker system prune -a
```

---

## API Errors

### 422 Unprocessable Entity

**Cause**: Invalid request format

**Fix**: Check API documentation and validate JSON:
```bash
# Use jq to validate
echo '{"key": "value"}' | jq .

# Check request matches API spec
curl -X POST http://localhost:8100/analyze \
  -H "Content-Type: application/json" \
  -d @test/sample-alert.json -v
```

### 503 Service Unavailable

**Cause**: Service down or unhealthy

**Fix**:
```bash
# Check health
curl http://localhost:8100/health

# Restart service
docker restart alert-triage

# Check logs
docker logs alert-triage --tail 100
```

---

## Common Error Messages

### "chromadb.errors.InvalidHTTPVersion"

**Cause**: ChromaDB client/server version mismatch

**Fix**:
```bash
pip install chromadb==0.5.23  # Match server version
```

### "ML Inference service error: 422"

**Cause**: Wrong number of features (needs 77, not 78)

**Fix**: Check feature vector length in request

### "Alert Triage timeout"

**Cause**: Ollama model not responding

**Fix**:
```bash
docker restart ollama
sleep 30
curl http://localhost:11434/api/tags
```

---

## Getting More Help

### Collect Diagnostics

```bash
#!/bin/bash
# Save as: collect-diagnostics.sh

echo "=== System Info ==="
uname -a
docker --version

echo "=== Docker Containers ==="
docker ps -a

echo "=== Service Health ==="
curl -s http://localhost:8002/health | jq .
curl -s http://localhost:8100/health | jq .
curl -s http://localhost:8001/health | jq .
curl -s http://localhost:8500/health | jq .

echo "=== Recent Logs ==="
docker logs alert-triage --tail 50 2>&1
docker logs rag-service --tail 50 2>&1
docker logs ids-inference --tail 50 2>&1

echo "=== Prometheus Targets ==="
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# Save to file
# ./collect-diagnostics.sh > diagnostics.txt 2>&1
```

### Report Issues

When reporting issues, include:
1. Error message (exact text)
2. Relevant logs
3. System info (OS, Docker version, RAM)
4. Steps to reproduce
5. Output of diagnostic script

---

**Last Updated**: 2026-01-20
=======
# Troubleshooting Guide
## Wazuh-CrewAI Threat Intelligence System

Common issues and their solutions.

---

## Quick Diagnosis

### System Health Check

```bash
# Check all services
sudo docker ps --format "table {{.Names}}\t{{.Status}}"

# Check service health
curl http://localhost:8002/health  # Integration Gateway
curl http://localhost:8100/health  # Alert Triage
curl http://localhost:8001/health  # RAG Service
curl http://localhost:8500/health  # ML Inference

# Check logs
docker logs alert-triage --tail 50
docker logs rag-service --tail 50
docker logs ids-inference --tail 50
```

---

## Service Won't Start

### Issue: Docker Container Exits Immediately

**Diagnosis**:
```bash
docker logs <container_name>
```

**Common Causes**:

1. **Missing Environment Variables**
```bash
# Check .env file exists
ls -la .env

# Verify API keys set
grep VIRUSTOTAL_API_KEY .env
```

**Fix**: Copy `.env.example` to `.env` and add API keys

2. **Port Already in Use**
```bash
sudo lsof -i :8100
```

**Fix**: Kill process or change port in docker-compose.yml

3. **Insufficient Memory**
```bash
docker stats
```

**Fix**: Increase Docker memory to 16GB+

---

## Port Configuration Issues

### Issue: Services on Wrong Ports

**Your deployment**:
- RAG Service: Port 8001 (should be 8200)
- ML Inference: Port 8500 (should be 8300)

**Fix**: Update `main-wazuh-integration.py`:

```python
# Line 28-30
RAG_SERVICE_URL = "http://localhost:8001/retrieve"    # NOT 8200
ML_SERVICE_URL = "http://localhost:8500/predict"      # NOT 8300
```

Restart integration service after change.

---

## CrewAI Investigation Fails

### Issue: Investigation Times Out or Errors

**Diagnosis**:
```bash
python test/test_crewai_investigation.py
```

**Common Causes**:

1. **External API Keys Invalid**
```python
# Test VirusTotal
curl https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8 \
  -H "x-apikey: YOUR_KEY"

# Test AbuseIPDB
curl https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8 \
  -H "Key: YOUR_KEY"
```

**Fix**: Get valid API keys and update `.env`

2. **YETI Authentication Failed**
```bash
# Check YETI credentials
grep YETI_ .env

# Test YETI connection
curl -X POST http://192.168.217.128:8000/api/v2/auth/token \
  -d "username=admin&password=your_password"
```

**Fix**: Update YETI_PASSWORD in `.env` or disable YETI tool

3. **Groq API Rate Limit**
```
INFO:httpx:HTTP Request: POST https://api.groq.com/openai/v1/chat/completions "HTTP/1.1 429 Too Many Requests"
```

**Fix**: Wait 1 minute or upgrade Groq plan

---

## Microservice Connection Issues

### Issue: Integration Gateway Can't Reach Services

**Error**: `Cannot connect to http://localhost:8100`

**Diagnosis**:
```bash
# Test from host
curl http://localhost:8100/health

# Check Docker network
docker network ls
docker network inspect monitoring
```

**Fix**:

If running integration gateway **outside Docker**, use:
```python
ALERT_TRIAGE_URL = "http://localhost:8100/analyze"
RAG_SERVICE_URL = "http://localhost:8001/retrieve"
ML_SERVICE_URL = "http://localhost:8500/predict"
```

If running integration gateway **inside Docker**, use:
```python
ALERT_TRIAGE_URL = "http://alert-triage:8000/analyze"
RAG_SERVICE_URL = "http://rag-service:8000/retrieve"
ML_SERVICE_URL = "http://ids-inference:8000/predict"
```

---

## Database & Storage Issues

### Issue: ChromaDB Connection Failed

**Error**: `chromadb.errors.ChromaClientException: Could not connect to tenant default_tenant`

**Fix**:
```bash
# Restart ChromaDB
docker restart chromadb

# Wait 30 seconds
sleep 30

# Test connection
curl http://localhost:8000/api/v1/heartbeat
```

### Issue: Ollama Model Not Loaded

**Error**: `Model llama3.2:3b not found`

**Fix**:
```bash
# List models
docker exec ollama ollama list

# Pull model if missing
docker exec ollama ollama pull llama3.2:3b

# Verify
docker exec ollama ollama run llama3.2:3b "test"
```
### Issue: Docker Containers Cannot Connect to Host Ollama

**Error**: `Ollama health check failed: All connection attempts failed`

**Symptoms**:
```json
{
  "status": "degraded",
  "ollama_connected": false,
  "ml_api_connected": true
}
```

**Diagnosis**:
```bash
# Test from HOST - works
curl http://127.0.0.1:11434/api/tags

# Test from Docker - fails
docker run --rm curlimages/curl:latest curl http://172.17.0.1:11434/api/tags
# Error: Connection refused
```

**Root Cause**:

By default, Ollama service listens only on `127.0.0.1:11434` (localhost), which is NOT accessible from Docker containers. Docker containers need Ollama to listen on `0.0.0.0:11434` (all network interfaces) to connect via the Docker bridge network gateway (usually `172.17.0.1`).

**Fix**:

Configure Ollama to listen on all interfaces:
```bash
# Step 1: Stop Ollama service
sudo systemctl stop ollama

# Step 2: Create systemd override configuration
sudo mkdir -p /etc/systemd/system/ollama.service.d/
sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null <<EOF
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF

# Step 3: Reload systemd and restart Ollama
sudo systemctl daemon-reload
sudo systemctl start ollama

# Step 4: Verify Ollama is listening on all interfaces
sudo ss -tlnp | grep 11434
# Should show: LISTEN 0 4096 *:11434 *:*

# Step 5: Test from Docker
docker run --rm curlimages/curl:latest curl http://172.17.0.1:11434/api/tags
# Should return JSON with model list

# Step 6: Restart alert-triage service
docker restart alert-triage

# Step 7: Verify connection
sleep 10
curl http://localhost:8100/health | jq
# Should show: "ollama_connected": true
```

**Security Note**: 

Binding Ollama to `0.0.0.0:11434` makes it accessible on all network interfaces. For production:

1. **Add firewall rules** to restrict access:
```bash
sudo ufw allow from 172.17.0.0/16 to any port 11434
sudo ufw deny 11434
```

2. **Or use Docker network** instead of host networking (run Ollama in Docker):
```bash
docker run -d --name ollama \
  --network ai_soc_network \
  -v ollama-data:/root/.ollama \
  ollama/ollama
```

**Alternative Solution (Docker Ollama)**:

If you prefer to keep Ollama isolated, run it inside Docker:
```bash
# Stop host Ollama
sudo systemctl stop ollama
sudo systemctl disable ollama

# Start Ollama in Docker
docker run -d --name ollama \
  --network ai_soc_network \
  -v ollama-data:/root/.ollama \
  ollama/ollama

# Pull cloud model inside container
docker exec ollama ollama pull gemini-3-flash-preview:cloud

# Update alert-triage to use Docker Ollama
docker stop alert-triage
docker rm alert-triage

docker run -d --name alert-triage \
  --network ai_soc_network \
  -p 8100:8000 \
  -e TRIAGE_OLLAMA_HOST=http://ollama:11434 \
  -e TRIAGE_PRIMARY_MODEL=gemini-3-flash-preview:cloud \
  alert-triage:latest
```
---

### Issue: Services on Different Docker Networks

**Error**: Services cannot communicate despite being running

**Symptoms**:
- `curl http://localhost:8100/health` shows `"ml_api_connected": false`
- Logs show: `ML API health check failed: All connection attempts failed`

**Root Cause**:

Services were deployed on different Docker networks:
- `alert-triage` → `ai_soc_network` + `rag-service_soc-network`
- `ids-inference` → `ai_soc` network
- `rag-service` → `soc-network`
- `chromadb` → `soc-network`

Docker networks are isolated - containers on different networks cannot communicate.

**Fix**:

Put all services on ONE unified network:
```bash
# Step 1: Stop all containers
docker stop alert-triage rag-service ids-inference chromadb
docker rm alert-triage rag-service ids-inference chromadb

# Step 2: Remove old networks and create unified network
docker network rm ai_soc_network soc-network ai_soc 2>/dev/null || true
docker network create ai_soc_network

# Step 3: Start all services on same network
docker run -d --name chromadb \
  --network ai_soc_network \
  -p 8000:8000 \
  chromadb/chroma:latest

docker run -d --name rag-service \
  --network ai_soc_network \
  -p 8001:8000 \
  -e CHROMADB_HOST=chromadb \
  -e CHROMADB_PORT=8000 \
  rag-service:latest

docker run -d --name ids-inference \
  --network ai_soc_network \
  -p 8500:8000 \
  -v $(pwd)/services/ml_training/models:/app/models:ro \
  ids-inference:latest

docker run -d --name alert-triage \
  --network ai_soc_network \
  -p 8100:8000 \
  -e TRIAGE_OLLAMA_HOST=http://172.17.0.1:11434 \
  -e TRIAGE_PRIMARY_MODEL=gemini-3-flash-preview:cloud \
  -e TRIAGE_ML_API_URL=http://ids-inference:8000 \
  alert-triage:latest

# Step 4: Verify connectivity
docker network inspect ai_soc_network | grep -A 5 "Containers"
```

**Best Practice**:

Use Docker Compose to manage networks automatically:
```yaml
# docker-compose.yml
version: '3.8'

networks:
  ai_soc_network:
    driver: bridge

services:
  chromadb:
    networks:
      - ai_soc_network
  
  rag-service:
    networks:
      - ai_soc_network
  
  ids-inference:
    networks:
      - ai_soc_network
  
  alert-triage:
    networks:
      - ai_soc_network
```
---

### Issue: ML Inference Port Mismatch

**Error**: `ML API health check failed`

**Root Cause**:

Alert-triage was configured to call `http://ids-inference:8500` but the ML service listens on port `8000` INSIDE the container (mapped to `8500` externally).

**Fix**:

Use the **internal** port when calling from Docker:
```bash
# Correct configuration
-e TRIAGE_ML_API_URL=http://ids-inference:8000

# NOT this (8500 is external port mapping)
-e TRIAGE_ML_API_URL=http://ids-inference:8500
```

**Rule**: 
- **External calls** (from HOST): Use mapped port (`localhost:8500`)
- **Internal calls** (Docker-to-Docker): Use container port (`ids-inference:8000`)
---

## PDF Report Generation Fails

### Issue: No PDF Generated

**Diagnosis**:
```bash
ls -lh reports/
```

**Common Causes**:

1. **Missing reportlab library**
```bash
pip install reportlab
```

2. **Write permissions**
```bash
chmod 777 reports/
```

3. **Investigation didn't complete**
```bash
# Check logs
docker logs wazuh-integration | grep "Investigation completed"
```

---

## Performance Issues

### Issue: Slow Investigation (>180 seconds)

**Expected**: 90-120 seconds
**Yours**: >180 seconds

**Diagnosis**:
```bash
# Check which agent is slow
docker logs wazuh-integration | grep "Agent:"
```

**Common Bottlenecks**:

1. **Groq API Latency** - Rate limits or slow responses
2. **External API Timeouts** - VirusTotal/AbuseIPDB slow
3. **YETI Failure** - Waiting for timeout on failed auth

**Fix**: Disable slow/failing tools temporarily:

```python
# In agents.yaml, comment out problematic agents
# coordinator_agent:
#   role: ...

# Or increase timeouts in tools/
```

---

## Monitoring Issues

### Issue: Prometheus Not Scraping

**Diagnosis**:
```bash
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
```

**Fix**:
```bash
# 1. Check service exposes /metrics
curl http://localhost:8100/metrics

# 2. Update prometheus.yml if needed
nano config/prometheus/prometheus.yml

# 3. Reload Prometheus
docker exec prometheus kill -HUP 1
```

### Issue: Loki Not Receiving Logs

**Fix**:
```bash
# Restart Promtail
docker restart promtail

# Check Promtail logs
docker logs promtail | grep -i error

# Test Loki
curl http://localhost:3100/ready
```

---

## Memory / Resource Issues

### Issue: Out of Memory

**Symptoms**:
- Docker containers killed (OOM)
- System freeze
- Services crash randomly

**Diagnosis**:
```bash
docker stats
free -h
```

**Fix**:

1. **Increase Docker memory** (Docker Desktop → Settings → Resources)
2. **Add resource limits** to docker-compose.yml:
```yaml
services:
  alert-triage:
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 2G
```

3. **Stop unused services**:
```bash
docker-compose down
docker system prune -a
```

---

## API Errors

### 422 Unprocessable Entity

**Cause**: Invalid request format

**Fix**: Check API documentation and validate JSON:
```bash
# Use jq to validate
echo '{"key": "value"}' | jq .

# Check request matches API spec
curl -X POST http://localhost:8100/analyze \
  -H "Content-Type: application/json" \
  -d @test/sample-alert.json -v
```

### 503 Service Unavailable

**Cause**: Service down or unhealthy

**Fix**:
```bash
# Check health
curl http://localhost:8100/health

# Restart service
docker restart alert-triage

# Check logs
docker logs alert-triage --tail 100
```

---

## Common Error Messages

### "chromadb.errors.InvalidHTTPVersion"

**Cause**: ChromaDB client/server version mismatch

**Fix**:
```bash
pip install chromadb==0.5.23  # Match server version
```

### "ML Inference service error: 422"

**Cause**: Wrong number of features (needs 77, not 78)

**Fix**: Check feature vector length in request

### "Alert Triage timeout"

**Cause**: Ollama model not responding

**Fix**:
```bash
docker restart ollama
sleep 30
curl http://localhost:11434/api/tags
```

---

## Getting More Help

### Collect Diagnostics

```bash
#!/bin/bash
# Save as: collect-diagnostics.sh

echo "=== System Info ==="
uname -a
docker --version

echo "=== Docker Containers ==="
docker ps -a

echo "=== Service Health ==="
curl -s http://localhost:8002/health | jq .
curl -s http://localhost:8100/health | jq .
curl -s http://localhost:8001/health | jq .
curl -s http://localhost:8500/health | jq .

echo "=== Recent Logs ==="
docker logs alert-triage --tail 50 2>&1
docker logs rag-service --tail 50 2>&1
docker logs ids-inference --tail 50 2>&1

echo "=== Prometheus Targets ==="
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# Save to file
# ./collect-diagnostics.sh > diagnostics.txt 2>&1
```

### Report Issues

When reporting issues, include:
1. Error message (exact text)
2. Relevant logs
3. System info (OS, Docker version, RAM)
4. Steps to reproduce
5. Output of diagnostic script

---

**Last Updated**: 2026-01-20
>>>>>>> dev
**Next**: See [DEVELOPMENT.md](DEVELOPMENT.md) for contributing