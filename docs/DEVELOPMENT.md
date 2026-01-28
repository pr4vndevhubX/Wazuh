# Development Guide
## Wazuh-CrewAI Threat Intelligence System

Guide for developers contributing to the project.

---

## Development Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- Code editor (VS Code recommended)

### Local Environment Setup

```bash
# Clone repository
git clone <repo-url>
cd Threat-Intelligence-with-SIEM

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development tools

# Install pre-commit hooks
pre-commit install
```

---

## Project Structure

```
Threat-Intelligence-with-SIEM/
├── main-wazuh-integration.py      # Integration gateway
├── crew.py                         # CrewAI orchestration
├── config/
│   ├── agents.yaml                 # Agent definitions
│   ├── tasks.yaml                  # Task definitions
│   ├── prometheus/                 # Monitoring configs
│   ├── grafana/                    # Dashboard configs
│   └── loki/                       # Log aggregation
├── tools/                          # CrewAI tools
│   ├── virustotal_tool.py
│   ├── abuseipdb_tool.py
│   ├── yeti_tool.py
│   ├── wazuh_siem_tool.py
│   ├── ml_inference_tool.py
│   ├── alert_triage_tool.py
│   └── rag_tool.py
├── services/                       # Microservices
│   ├── alert-triage/
│   │   ├── main.py
│   │   ├── llm_client.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── rag-service/
│   │   ├── main.py
│   │   ├── vector_store.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── ml-inference/
│       ├── inference_api.py
│       ├── Dockerfile
│       └── requirements.txt
├── test/                           # Test suite
│   ├── test_wazuh_integration.py
│   └── test_crewai_investigation.py
├── utils/                          # Utilities
│   ├── pdf_generator.py
│   └── db_path.py
└── docs/                           # Documentation
    ├── README.md
    ├── QUICKSTART.md
    ├── INSTALLATION.md
    ├── ARCHITECTURE.md
    ├── API_REFERENCE.md
    ├── MONITORING.md
    ├── TROUBLESHOOTING.md
    └── DEVELOPMENT.md
```

---

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

Follow coding standards (see below)

### 3. Test Locally

```bash
# Run unit tests
pytest test/

# Run integration tests
python test/test_wazuh_integration.py
python test/test_crewai_investigation.py

# Lint code
black .
flake8 .
mypy .
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature"
# Commit message format: <type>: <description>
# Types: feat, fix, docs, style, refactor, test, chore
```

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
# Create Pull Request on GitHub
```

---

## Coding Standards

### Python Style Guide

- Follow PEP 8
- Use type hints
- Max line length: 100 characters
- Use `black` for formatting
- Use `flake8` for linting

**Example**:
```python
from typing import Dict, List, Optional

def process_alert(
    alert: Dict[str, Any],
    enrich: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Process security alert with optional enrichment.
    
    Args:
        alert: Alert dictionary from Wazuh
        enrich: Whether to enrich with ML/LLM
        
    Returns:
        Processed alert or None if invalid
    """
    if not validate_alert(alert):
        return None
    
    # Process alert
    result = triage_alert(alert)
    
    if enrich:
        result = enrich_alert(result)
    
    return result
```

### FastAPI Conventions

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Service Name",
    version="1.0.0",
    docs_url="/docs"
)

class AlertRequest(BaseModel):
    """Alert request model with validation."""
    alert_id: str = Field(..., description="Alert identifier")
    severity: int = Field(..., ge=1, le=15, description="Alert severity")

@app.post("/analyze", response_model=AlertResponse)
async def analyze_alert(request: AlertRequest):
    """
    Analyze security alert.
    
    Returns enriched alert with severity assessment.
    """
    try:
        result = await process(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

---

## Adding New Features

### Adding a New Agent

1. **Update `config/agents.yaml`**:
```yaml
new_agent:
  role: "Role Description"
  goal: "Agent goal"
  backstory: |
    Agent backstory with context
```

2. **Create agent in `crew.py`**:
```python
@agent
def new_agent(self) -> Agent:
    """Agent description."""
    return Agent(
        config=self.agents_config['new_agent'],
        llm=llm,
        tools=[new_tool],
        verbose=True
    )
```

3. **Add corresponding task**:
```python
@task
def task_new_agent(self) -> Task:
    """Task description."""
    return Task(
        config=self.tasks_config['task_new_agent'],
        agent=self.new_agent(),
        context=[self.task_coordinator()]
    )
```

### Adding a New Tool

1. **Create tool file** `tools/new_tool.py`:
```python
from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field

class NewToolInput(BaseModel):
    """Input schema for NewTool."""
    param: str = Field(..., description="Parameter description")

class NewTool(BaseTool):
    name: str = "Tool Name"
    description: str = "Tool description for agent"
    args_schema: Type[BaseModel] = NewToolInput
    
    def _run(self, param: str) -> dict:
        """
        Execute tool logic.
        
        Args:
            param: Input parameter
            
        Returns:
            Tool result dictionary
        """
        # Implementation
        result = external_api_call(param)
        return {"status": "success", "data": result}
```

2. **Import in `crew.py`**:
```python
from tools.new_tool import NewTool
new_tool = NewTool()
```

### Adding a New Microservice

1. **Create service directory**:
```bash
mkdir -p services/new-service
cd services/new-service
```

2. **Create FastAPI app** (`main.py`):
```python
from fastapi import FastAPI
from prometheus_client import Counter, Histogram, generate_latest

app = FastAPI(title="New Service")

# Metrics
requests_total = Counter('requests_total', 'Total requests')
request_duration = Histogram('request_duration_seconds', 'Duration')

@app.post("/process")
async def process(data: dict):
    requests_total.inc()
    with request_duration.time():
        result = process_logic(data)
    return result

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type="text/plain")
```

3. **Create Dockerfile**:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

4. **Add to docker-compose.yml**:
```yaml
services:
  new-service:
    build:
      context: ../services/new-service
      dockerfile: Dockerfile
    image: new-service:latest
    container_name: new-service
    ports:
      - "8600:8000"
    networks:
      - ai-services
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## Testing

### Unit Tests

```python
import pytest
from tools.virustotal_tool import VirusTotalTool

def test_virustotal_tool():
    """Test VirusTotal tool."""
    tool = VirusTotalTool()
    result = tool._run("8.8.8.8")
    
    assert "source" in result
    assert result["source"] == "VirusTotal"
    assert "verdict" in result
```

### Integration Tests

```python
import requests

def test_alert_triage_api():
    """Test alert triage service."""
    response = requests.post(
        "http://localhost:8100/analyze",
        json={
            "rule_description": "Test alert",
            "rule_level": 10,
            "source_ip": "192.168.1.100"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "severity" in data
    assert "confidence" in data
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test
pytest test/test_wazuh_integration.py -v

# Run integration tests only
pytest -m integration
```

---

## Debugging

### Local Debugging

**VS Code** (`launch.json`):
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Integration Gateway",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/main-wazuh-integration.py",
      "console": "integratedTerminal",
      "env": {
        "PYTHONPATH": "${workspaceFolder}"
      }
    },
    {
      "name": "CrewAI Test",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/test/test_crewai_investigation.py",
      "console": "integratedTerminal"
    }
  ]
}
```

### Docker Debugging

```bash
# Attach to running container
docker exec -it alert-triage /bin/bash

# View logs with follow
docker logs -f alert-triage

# Run service with debug mode
docker run -it --rm \
  -p 8100:8000 \
  -e DEBUG=true \
  alert-triage:latest
```

---

## Performance Optimization

### Profiling

```python
import cProfile
import pstats

# Profile function
profiler = cProfile.Profile()
profiler.enable()

result = expensive_function()

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)
```

### Async Optimization

```python
import asyncio
import httpx

# Parallel API calls
async def fetch_all_intel(ip: str):
    async with httpx.AsyncClient() as client:
        tasks = [
            client.get(f"https://virustotal.com/api/{ip}"),
            client.get(f"https://abuseipdb.com/api/{ip}"),
            client.get(f"http://yeti:8000/api/{ip}")
        ]
        results = await asyncio.gather(*tasks)
    return results
```

---

## Documentation

### Docstring Format

```python
def process_alert(alert: dict, enrich: bool = True) -> dict:
    """
    Process security alert with optional enrichment.
    
    This function validates the alert format, performs triage,
    and optionally enriches with ML and LLM analysis.
    
    Args:
        alert: Alert dictionary containing:
            - rule_id: Wazuh rule identifier
            - severity: Alert severity (1-15)
            - source_ip: Source IP address
        enrich: Whether to enrich with ML/LLM analysis
        
    Returns:
        Processed alert with enrichment data:
            - severity: Assessed severity
            - confidence: Confidence score
            - iocs: Extracted indicators
            
    Raises:
        ValueError: If alert format is invalid
        
    Example:
        >>> alert = {"rule_id": "5710", "severity": 10}
        >>> result = process_alert(alert, enrich=True)
        >>> print(result["severity"])
        "high"
    """
```

---

## Contributing Guidelines

### Pull Request Process

1. Update documentation
2. Add tests for new features
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review from maintainers

### Code Review Checklist

- [ ] Code follows style guide
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
- [ ] Performance impact assessed
- [ ] Security implications reviewed

---

## Release Process

### Version Numbering

Use Semantic Versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### Creating a Release

```bash
# Update version
echo "1.1.0" > VERSION

# Update CHANGELOG.md
# Tag release
git tag -a v1.1.0 -m "Release 1.1.0"
git push origin v1.1.0

# Build Docker images
docker build -t crewai-alert-triage:1.1.0 services/alert-triage/
docker build -t crewai-rag-service:1.1.0 services/rag-service/
docker build -t crewai-ml-inference:1.1.0 services/ml-inference/

# Push to registry
docker push crewai-alert-triage:1.1.0
```

---

**Last Updated**: 2026-01-20
**Questions?** Open an issue on GitHub