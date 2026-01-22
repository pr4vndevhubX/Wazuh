# Installation Guide
## Wazuh-CrewAI Threat Intelligence System

Complete installation instructions for production deployment.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Pre-Installation Checklist](#pre-installation-checklist)
3. [Installation Methods](#installation-methods)
4. [Step-by-Step Installation](#step-by-step-installation)
5. [Wazuh SIEM Deployment](#wazuh-siem-deployment)
6. [Service Configuration](#service-configuration)
7. [Integration Testing](#integration-testing)
8. [Post-Installation Tasks](#post-installation-tasks)
9. [Production Hardening](#production-hardening)

---

## System Requirements

### Minimum Requirements

| Component | Specification |
|-----------|---------------|
| **Operating System** | Ubuntu 20.04+, RHEL 8+, or WSL2 |
| **CPU** | 4 cores (8 recommended) |
| **RAM** | 16GB (32GB recommended) |
| **Disk Space** | 50GB available (SSD preferred) |
| **Docker** | 24.0+ with Compose V2 |
| **Python** | 3.11+ |
| **Network** | Internet access for image downloads |

### Recommended Production Specs

| Component | Specification |
|-----------|---------------|
| **CPU** | 8+ cores (Intel Xeon or AMD EPYC) |
| **RAM** | 32GB+ ECC memory |
| **Disk** | 200GB+ NVMe SSD |
| **Network** | 1Gbps network interface |
| **Backup** | Separate volume for data persistence |

---

## Pre-Installation Checklist

### 1. Verify System Resources

```bash
# Check CPU cores
nproc
# Should show: 4 or more

# Check available RAM
free -h
# Should show: 16GB+ available

# Check disk space
df -h /
# Should show: 50GB+ available

# Check Docker version
docker --version
# Should show: 24.0+

# Check Docker Compose
docker-compose --version
# Should show: 2.20+
```

### 2. Configure System Settings

**Linux - Increase max_map_count** (Required for Wazuh Indexer):

```bash
# Temporary (until reboot)
sudo sysctl -w vm.max_map_count=262144

# Permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Linux - Increase file descriptors**:

```bash
# Check current limits
ulimit -n

# Set to 65536
sudo bash -c 'cat >> /etc/security/limits.conf << EOF
* soft nofile 65536
* hard nofile 65536
EOF'
```

### 3. Install Dependencies

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install -y \
    curl \
    git \
    python3.11 \
    python3-pip \
    docker.io \
    docker-compose-v2
```

**RHEL/CentOS**:
```bash
sudo yum install -y \
    curl \
    git \
    python3.11 \
    python3-pip \
    docker \
    docker-compose
```

**Enable Docker service**:
```bash
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group (logout/login required)
sudo usermod -aG docker $USER
```

### 4. Prepare API Keys

You need accounts and API keys from:

1. **VirusTotal**: https://www.virustotal.com/gui/join-us
   - Free tier: 500 requests/day
   - Get API key from: Account → API Key

2. **AbuseIPDB**: https://www.abuseipdb.com/register
   - Free tier: 1000 requests/day
   - Get API key from: Account → API

3. **Groq**: https://console.groq.com/keys
   - Free tier available
   - Model: llama-3.3-70b-versatile

4. **YETI** (Optional): Deploy your own or use existing instance
   - Community version: https://github.com/yeti-platform/yeti

---

## Installation Methods

### Method 1: Automated Installation (Recommended)

```bash
# Clone repository
git clone <your-repo-url>
cd Threat-Intelligence-with-SIEM

# Run installation script
./scripts/install.sh
```

### Method 2: Manual Installation (This Guide)

Follow the step-by-step instructions below for full control.

---

## Step-by-Step Installation

### Step 1: Clone Repository

```bash
# Clone from GitHub
git clone <your-repo-url>
cd Threat-Intelligence-with-SIEM

# Verify files
ls -la
# Should see: docker-compose/, services/, config/, tools/, etc.
```

### Step 2: Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Required Environment Variables**:

```bash
# ===== External Threat Intelligence =====
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# ===== LLM Configuration =====
OPENROUTER_API_KEY=your_groq_api_key_here
OPENROUTER_MODEL=llama-3.3-70b-versatile
OPENROUTER_API_BASE=https://api.groq.com/openai/v1

# ===== YETI Platform (Optional) =====
YETI_URL=http://192.168.217.128:8000
YETI_USERNAME=admin
YETI_PASSWORD=change_me_secure_password

# ===== Service Ports =====
WAZUH_INTEGRATION_PORT=8002
ALERT_TRIAGE_PORT=8100
RAG_SERVICE_PORT=8001
ML_INFERENCE_PORT=8500
PROMETHEUS_PORT=9090
LOKI_PORT=3100
CHROMADB_PORT=8000
OLLAMA_PORT=11434

# ===== Wazuh Configuration (if deploying) =====
WAZUH_INDEXER_PASSWORD=SecurePassword123!
WAZUH_API_PASSWORD=SecurePassword456!

# ===== Monitoring =====
GRAFANA_ADMIN_PASSWORD=admin123
```

**Save the file** (Ctrl+X, Y, Enter in nano).

### Step 3: Fix Port Mappings

Your deployment uses non-standard ports. Update the integration service:

```bash
nano main-wazuh-integration.py
```

Find lines 28-30 and change:

```python
# BEFORE (incorrect):
RAG_SERVICE_URL = "http://localhost:8200/query"
ML_SERVICE_URL = "http://localhost:8300/predict"

# AFTER (correct for your deployment):
RAG_SERVICE_URL = "http://localhost:8001/retrieve"
ML_SERVICE_URL = "http://localhost:8500/predict"
```

Save and exit.

### Step 4: Deploy AI Services

```bash
# Navigate to docker-compose directory
cd docker-compose

# Start AI services stack
docker-compose -f ai-services.yml up -d

# Verify services started
docker-compose -f ai-services.yml ps
```

**Expected Output**:
```
NAME            STATUS              PORTS
alert-triage    Up (healthy)        0.0.0.0:8100->8000/tcp
rag-service     Up (healthy)        0.0.0.0:8001->8000/tcp
ids-inference   Up (healthy)        0.0.0.0:8500->8000/tcp
chromadb        Up                  0.0.0.0:8000->8000/tcp
ollama          Up                  11434/tcp
```

**Wait 2-3 minutes** for health checks to pass.

### Step 5: Deploy Monitoring Stack

```bash
# Still in docker-compose/ directory
docker-compose -f monitoring-stack.yml up -d

# Verify monitoring services
docker-compose -f monitoring-stack.yml ps
```

**Expected Output**:
```
NAME           STATUS    PORTS
prometheus     Up        0.0.0.0:9090->9090/tcp
loki           Up        0.0.0.0:3100->3100/tcp
promtail       Up        (no exposed ports)
```

### Step 6: Start Integration Gateway

```bash
# Navigate to integration service
cd ../services/wazuh-integration

# Install Python dependencies
pip install -r requirements.txt

# Start service (use screen or tmux for persistent session)
python main.py

# Or run in background
nohup python main.py > ../../logs/wazuh-integration.log 2>&1 &
```

### Step 7: Verify All Services

```bash
# Health check script
curl http://localhost:8002/health  # Integration Gateway
curl http://localhost:8100/health  # Alert Triage
curl http://localhost:8001/health  # RAG Service
curl http://localhost:8500/health  # ML Inference
curl http://localhost:9090/-/healthy  # Prometheus
curl http://localhost:3100/ready  # Loki
```

**All should return HTTP 200 OK**.

---

## Wazuh SIEM Deployment

### Option A: Use Existing Wazuh Installation

If you already have Wazuh deployed:

1. Configure webhook integration (see [Service Configuration](#service-configuration))
2. Skip to [Integration Testing](#integration-testing)

### Option B: Deploy Wazuh with Docker Compose

```bash
cd docker-compose

# Deploy Wazuh stack
docker-compose -f wazuh-stack.yml up -d

# Wait 5-10 minutes for initialization
docker-compose -f wazuh-stack.yml logs -f wazuh-manager
```

**Verify Wazuh Dashboard**:
- URL: https://localhost:443
- Username: `admin`
- Password: Check `WAZUH_INDEXER_PASSWORD` in `.env`

### Option C: Deploy Wazuh on Separate Server

Follow official Wazuh installation guide:
- https://documentation.wazuh.com/current/installation-guide/

Then configure webhook to point to your Integration Gateway.

---

## Service Configuration

### 1. Wazuh Webhook Integration

**Edit Wazuh Manager configuration**:

```bash
# SSH to Wazuh Manager
ssh user@wazuh-manager-ip

# Edit ossec.conf
sudo nano /var/ossec/etc/ossec.conf
```

**Add integration block**:

```xml
<ossec_config>
  <integration>
    <name>custom-webhook</name>
    <hook_url>http://192.168.217.122:8002/webhook</hook_url>
    <level>8</level>
    <alert_format>json</alert_format>
    <api_key>Apkl3@Jfyg2</api_key>
  </integration>
</ossec_config>
```

**Restart Wazuh Manager**:

```bash
sudo systemctl restart wazuh-manager
```

### 2. YETI Platform Configuration

**Update tool configuration**:

```bash
nano tools/yeti_tool.py
```

Update credentials:

```python
base_url = os.getenv("YETI_URL", "http://192.168.217.128:8000")
username = os.getenv("YETI_USERNAME", "admin")
password = os.getenv("YETI_PASSWORD", "your_secure_password")
```

### 3. Prometheus Scrape Configuration

**Verify Prometheus is scraping all services**:

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
```

**Expected output**:
```json
{"job": "alert-triage", "health": "up"}
{"job": "rag-service", "health": "up"}
{"job": "ml-inference", "health": "up"}
{"job": "wazuh-integration", "health": "up"}
```

### 4. Grafana Setup (Optional)

If deploying Grafana separately:

```bash
# Deploy Grafana
docker run -d \
  --name=grafana \
  -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=admin123 \
  grafana/grafana:latest

# Access: http://localhost:3000
# Login: admin / admin123
```

**Add Prometheus datasource**:
- Navigate to Configuration → Data Sources
- Add Prometheus: `http://prometheus:9090`
- Save & Test

---

## Integration Testing

### Test 1: Service Health Checks

```bash
# Run automated test script
cd test
python test_wazuh_integration.py
```

**Expected Output**:
```
🏥 HEALTH CHECK
✅ Service is healthy

🧪 TEST: Level 3 - Should be ARCHIVED
✅ Response: {"status": "archived"}

🧪 TEST: Level 8 - Should trigger LLM TRIAGE
✅ Response: {"status": "processed", "triage_severity": "high"}

🧪 TEST: Level 12 - Should trigger FULL PIPELINE + FLAG
✅ Response: {"flagged_for_investigation": true}

✅ All tests completed!
```

### Test 2: CrewAI Investigation

```bash
# Run full investigation test
python test_crewai_investigation.py
```

**Expected Output**:
```
🚀 CrewAI Investigation Test

✅ Investigation completed successfully!
Status: success
IP Analyzed: 8.8.8.8
Execution Time: 102.97s
PDF Report: reports/IOC_Report_8_8_8_8_20260120_173424.pdf

Investigation Summary:
✅ VirusTotal: 0/97 vendors flagged
✅ AbuseIPDB: 0% abuse, Whitelisted
✅ ML Prediction: BENIGN (86% confidence)
✅ MITRE Context: 5 techniques retrieved
Verdict: BENIGN (96% confidence)
```

### Test 3: End-to-End Alert Flow

**Send test alert from Wazuh** (if deployed):

```bash
# Trigger test alert on Wazuh agent
sudo /var/ossec/bin/agent_control -r -u 001

# Or use API
curl -X POST http://localhost:8002/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: Apkl3@Jfyg2" \
  -d @test/sample-alert.json
```

**Verify alert processing**:

```bash
# Check integration service logs
tail -f logs/wazuh-integration.log

# Should see:
# ✅ Alert received: Level 10, IP: 192.168.1.100
# ✅ Starting LLM triage
# ✅ Triage result: high (confidence: 0.92)
# ✅ CRITICAL ALERT - Flagged for investigation
```

---

## Post-Installation Tasks

### 1. Create Service Users (Production)

```bash
# Create service account
sudo useradd -r -s /bin/false crewai-service

# Set permissions
sudo chown -R crewai-service:crewai-service /opt/Threat-Intelligence-with-SIEM
```

### 2. Configure Systemd Services

**Create systemd unit** (`/etc/systemd/system/wazuh-integration.service`):

```ini
[Unit]
Description=Wazuh Integration Gateway
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=crewai-service
WorkingDirectory=/opt/Threat-Intelligence-with-SIEM/services/wazuh-integration
ExecStart=/usr/bin/python3 main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start**:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-integration
sudo systemctl start wazuh-integration
sudo systemctl status wazuh-integration
```

### 3. Configure Log Rotation

**Create logrotate config** (`/etc/logrotate.d/crewai`):

```
/opt/Threat-Intelligence-with-SIEM/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 crewai-service crewai-service
    sharedscripts
    postrotate
        systemctl reload wazuh-integration > /dev/null 2>&1 || true
    endscript
}
```

### 4. Setup Automated Backups

```bash
# Create backup script
cat > /opt/Threat-Intelligence-with-SIEM/scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/crewai"
DATE=$(date +%Y%m%d)

# Backup configuration
tar -czf $BACKUP_DIR/config-$DATE.tar.gz config/

# Backup reports (last 7 days)
find reports/ -mtime -7 -type f -name "*.pdf" | tar -czf $BACKUP_DIR/reports-$DATE.tar.gz -T -

# Backup Docker volumes
docker run --rm -v chromadb-data:/data -v $BACKUP_DIR:/backup alpine tar -czf /backup/chromadb-$DATE.tar.gz /data

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -mtime +30 -delete
EOF

chmod +x /opt/Threat-Intelligence-with-SIEM/scripts/backup.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /opt/Threat-Intelligence-with-SIEM/scripts/backup.sh" | crontab -
```

---

## Production Hardening

### 1. Security Configuration

**Enable firewall rules**:

```bash
# Allow only necessary ports
sudo ufw allow 8002/tcp  # Integration Gateway
sudo ufw allow 9090/tcp  # Prometheus (internal only)
sudo ufw allow 3000/tcp  # Grafana
sudo ufw deny 8100/tcp   # Block Alert Triage external access
sudo ufw deny 8001/tcp   # Block RAG Service external access
sudo ufw deny 8500/tcp   # Block ML Inference external access
sudo ufw enable
```

**Generate strong secrets**:

```bash
# Generate secure API key
openssl rand -base64 32

# Update in .env
WAZUH_INTEGRATION_API_KEY=<generated-key>
```

### 2. TLS/SSL Configuration

**Generate SSL certificates** (production):

```bash
# Use Let's Encrypt
sudo apt install certbot
sudo certbot certonly --standalone -d your-domain.com

# Update docker-compose.yml to mount certificates
```

### 3. Resource Limits

**Update docker-compose.yml** with resource constraints:

```yaml
services:
  alert-triage:
    # ... existing config ...
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### 4. Monitoring Alerts

**Configure AlertManager notifications**:

```bash
nano config/alertmanager/alertmanager.yml
```

Add email/Slack configuration:

```yaml
receivers:
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
```

---

## Troubleshooting Installation

### Issue: Docker Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Logout and login, or run:
newgrp docker
```

### Issue: Port Already in Use

```bash
# Find process using port
sudo lsof -i :8100

# Kill process
sudo kill -9 <PID>

# Or change port in .env
```

### Issue: Service Won't Start

```bash
# Check logs
docker logs alert-triage

# Check if all environment variables are set
docker exec alert-triage env | grep API_KEY
```

### Issue: Out of Disk Space

```bash
# Clean Docker images
docker system prune -a

# Check volume usage
docker system df

# Remove unused volumes
docker volume prune
```

---

## Verification Checklist

After installation, verify:

- [ ] All Docker containers running (`docker ps`)
- [ ] All health checks passing
- [ ] Integration Gateway receiving alerts
- [ ] CrewAI investigation completes successfully
- [ ] PDF reports generated
- [ ] Prometheus collecting metrics
- [ ] Logs aggregated in Loki
- [ ] Wazuh webhook configured (if applicable)
- [ ] Firewall rules configured
- [ ] Backups scheduled
- [ ] Systemd services enabled

---

## Next Steps

1. **Configure Wazuh Agents**: Install agents on systems to monitor
2. **Customize Rules**: Edit `config/agents.yaml` and `config/tasks.yaml`
3. **Build Dashboard**: Create web UI for alert management
4. **Setup Notifications**: Configure Slack/email alerts
5. **Performance Tuning**: Optimize based on your alert volume

See [ARCHITECTURE.md](ARCHITECTURE.md) for system design details.

---

**Installation Complete!** 🎉

Your AI-powered threat intelligence system is now ready for production use.

**Support**: For issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

**Last Updated**: 2026-01-20