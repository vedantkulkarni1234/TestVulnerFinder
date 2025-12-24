# SOC-EATER v2 Deployment Guide

## Local Development

### Prerequisites
- Python 3.11+
- Google Gemini API key ([Get one free](https://ai.google.dev))
- 2GB RAM minimum
- Linux/macOS/Windows with WSL

### Setup

```bash
# Clone and navigate
cd soc_eater_v2

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set API key
export GEMINI_API_KEY=your_key_here

# Run
python soc_eater_v2/main.py
```

Open http://localhost:8000

### Configuration

Environment variables:

```bash
export GEMINI_API_KEY=AIza...           # Required
export HOST=0.0.0.0                     # Optional, default 0.0.0.0
export PORT=8000                        # Optional, default 8000
export LOG_LEVEL=info                   # Optional, default info
```

Or use `.env` file:

```bash
cp .env.example .env
nano .env  # Add your API key
```

---

## Docker Deployment

### Build Image

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt soc_eater_v2/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY soc_eater_v2/ ./soc_eater_v2/
COPY README.md ARCHITECTURE.md PLAYBOOKS.md ./

# Environment
ENV GEMINI_API_KEY=""
ENV HOST=0.0.0.0
ENV PORT=8000
ENV LOG_LEVEL=info

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run
CMD ["python", "-m", "soc_eater_v2.main"]
```

Build and run:

```bash
docker build -t soc-eater-v2 .

docker run -d \
  --name soc-eater-v2 \
  -p 8000:8000 \
  -e GEMINI_API_KEY=your_key_here \
  --restart unless-stopped \
  soc-eater-v2
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  soc-eater:
    build: .
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - HOST=0.0.0.0
      - PORT=8000
      - LOG_LEVEL=info
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
```

Run:

```bash
export GEMINI_API_KEY=your_key_here
docker-compose up -d
```

---

## Cloud Deployment

### Google Cloud Run

```bash
# Install gcloud CLI
gcloud auth login
gcloud config set project your-project-id

# Build and deploy
gcloud run deploy soc-eater-v2 \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=your_key_here \
  --memory 1Gi \
  --cpu 1 \
  --max-instances 10
```

### AWS ECS/Fargate

1. Push to ECR:

```bash
aws ecr create-repository --repository-name soc-eater-v2

docker tag soc-eater-v2:latest \
  123456789.dkr.ecr.us-east-1.amazonaws.com/soc-eater-v2:latest

aws ecr get-login-password | docker login --username AWS \
  --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/soc-eater-v2:latest
```

2. Create ECS task definition with environment variable `GEMINI_API_KEY` from AWS Secrets Manager
3. Deploy to Fargate cluster

### Azure Container Instances

```bash
az container create \
  --resource-group soc-eater-rg \
  --name soc-eater-v2 \
  --image soc-eater-v2:latest \
  --cpu 1 \
  --memory 2 \
  --ports 8000 \
  --environment-variables GEMINI_API_KEY=your_key_here \
  --dns-name-label soc-eater-v2
```

### Kubernetes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: soc-eater-v2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: soc-eater-v2
  template:
    metadata:
      labels:
        app: soc-eater-v2
    spec:
      containers:
      - name: soc-eater-v2
        image: soc-eater-v2:latest
        ports:
        - containerPort: 8000
        env:
        - name: GEMINI_API_KEY
          valueFrom:
            secretKeyRef:
              name: soc-eater-secrets
              key: gemini-api-key
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: soc-eater-v2-service
spec:
  selector:
    app: soc-eater-v2
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8000
  type: LoadBalancer
---
apiVersion: v1
kind: Secret
metadata:
  name: soc-eater-secrets
type: Opaque
data:
  gemini-api-key: <base64-encoded-key>
```

Deploy:

```bash
kubectl apply -f deployment.yaml
```

---

## Reverse Proxy

### NGINX

```nginx
# /etc/nginx/sites-available/soc-eater-v2
server {
    listen 80;
    server_name soc.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for large PCAP uploads
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
    }

    client_max_body_size 100M;
}
```

Enable and restart:

```bash
ln -s /etc/nginx/sites-available/soc-eater-v2 /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

### Traefik (Docker Labels)

```yaml
services:
  soc-eater:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.soc-eater.rule=Host(`soc.example.com`)"
      - "traefik.http.routers.soc-eater.entrypoints=websecure"
      - "traefik.http.routers.soc-eater.tls.certresolver=letsencrypt"
      - "traefik.http.services.soc-eater.loadbalancer.server.port=8000"
```

---

## Production Best Practices

### Security

1. **API Key Management**
   - Use secrets manager (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
   - Never commit keys to Git
   - Rotate keys regularly

2. **Authentication**
   - Add authentication layer (OAuth2, API keys)
   - Example with FastAPI:
   ```python
   from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
   
   security = HTTPBearer()
   
   @app.post("/analyze")
   async def analyze(credentials: HTTPAuthorizationCredentials = Depends(security)):
       # Verify token
       pass
   ```

3. **Rate Limiting**
   ```python
   from slowapi import Limiter
   from slowapi.util import get_remote_address
   
   limiter = Limiter(key_func=get_remote_address)
   app.state.limiter = limiter
   
   @app.post("/analyze")
   @limiter.limit("10/minute")
   async def analyze():
       pass
   ```

4. **Input Validation**
   - Already handled by Pydantic
   - Add file size limits
   - Validate file types

5. **HTTPS Only**
   - Use Let's Encrypt for TLS certificates
   - Enforce HTTPS in production

### Monitoring

1. **Logging**
   ```python
   import logging
   
   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
   )
   ```

2. **Metrics**
   - Track: requests/second, response time, error rate, cost per investigation
   - Use Prometheus + Grafana
   - Built-in `/stats` endpoint provides basic metrics

3. **Alerting**
   - Alert on error rate spikes
   - Alert on API key quota approaching limits
   - Alert on unusual cost increases

### Scaling

1. **Horizontal Scaling**
   - Run multiple instances behind load balancer
   - Each instance is stateless
   - Scale based on CPU/memory usage

2. **Queue System** (For high volume)
   ```python
   # Add Redis queue for async processing
   from rq import Queue
   from redis import Redis
   
   redis_conn = Redis()
   q = Queue(connection=redis_conn)
   
   @app.post("/analyze_async")
   async def analyze_async(prompt: str):
       job = q.enqueue(brain.analyze_incident, prompt=prompt)
       return {"job_id": job.id}
   ```

3. **Caching** (Optional)
   - Cache identical prompts for 1 hour
   - Use Redis or Memcached
   - Reduces costs for duplicate investigations

### Backup & Recovery

1. **Database** (If you add one)
   - Daily automated backups
   - Test restore procedures

2. **Configuration**
   - Version control all configs
   - Document deployment process

3. **Disaster Recovery**
   - Multi-region deployment for critical deployments
   - Automated failover

### Cost Optimization

1. **Gemini API**
   - Monitor token usage via `/stats` endpoint
   - Set up billing alerts in Google Cloud
   - Current rate: ~₹0.65-0.85 per investigation

2. **Infrastructure**
   - Use autoscaling (scale to zero during low usage)
   - Right-size instances (1 CPU, 2GB RAM typical)
   - Use spot/preemptible instances for non-critical workloads

---

## Integration Examples

### Splunk Alert Action

```python
# splunk_integration.py
import requests

SOCEATER_URL = "http://soc-eater:8000/analyze_json"

def send_to_soceater(alert_data):
    result = requests.post(SOCEATER_URL, json={
        "prompt": f"Splunk alert: {alert_data['search_name']}",
        "context": alert_data
    })
    return result.json()
```

### Microsoft Sentinel Playbook

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "Call_SOC_EATER": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "http://soc-eater:8000/analyze_json",
          "body": {
            "prompt": "@{triggerBody()?['AlertName']}",
            "context": "@{triggerBody()}"
          }
        }
      }
    }
  }
}
```

### Slack Bot

```python
from slack_bolt import App
import requests

app = App(token=os.environ["SLACK_BOT_TOKEN"])

@app.event("app_mention")
def handle_mention(event, say):
    text = event["text"]
    result = requests.post("http://soc-eater:8000/analyze_json", json={
        "prompt": text
    })
    say(result.json()["raw_analysis"])
```

---

## Troubleshooting

### API Key Issues

```
ValueError: GEMINI_API_KEY not found
```

**Solution:** Ensure environment variable is set correctly.

### PCAP Parser Errors

```
ImportError: No module named 'dpkt'
```

**Solution:** `pip install dpkt`

### Out of Memory

**Solution:** Increase Docker memory limit or use smaller PCAP files (reduce `max_packets` parameter).

### Rate Limiting

```
429 Too Many Requests
```

**Solution:** Gemini API has rate limits. Implement request queuing or backoff strategy.

---

## Support

- GitHub Issues: [Your repo]
- Documentation: This file + ARCHITECTURE.md + PLAYBOOKS.md
- Gemini API Docs: https://ai.google.dev/docs
