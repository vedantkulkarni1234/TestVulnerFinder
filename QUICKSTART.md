# SOC-EATER v2 - Quick Start Guide

## One-Minute Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set your Gemini API key
export GEMINI_API_KEY=your_key_here

# 3. Run
python soc_eater_v2/main.py
```

Open http://localhost:8000

---

## Get Gemini API Key (Free)

1. Visit https://ai.google.dev
2. Click "Get API key in Google AI Studio"
3. Create API key
4. Copy and export: `export GEMINI_API_KEY=AIza...`

---

## First Investigation

### Via Web UI (http://localhost:8000)

1. Paste this sample alert:
   ```
   Suspicious PowerShell execution detected:
   
   Host: WS-2023-001
   User: john.doe
   Command: powershell.exe -encodedCommand JABhAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0...
   Time: 2024-01-15 14:23:45 UTC
   Parent Process: outlook.exe
   
   EDR Alert: Process injection detected
   ```

2. Click "Submit"
3. Get full investigation report in 5-15 seconds

### Via API (curl)

```bash
curl -X POST http://localhost:8000/analyze \
  -F 'prompt=Investigate: User clicked on phishing email with attachment invoice.pdf. EDR detected suspicious network connection to 185.220.101.45.'
```

### Via Python

```python
from soc_eater_v2.soc_brain import SOCBrain

brain = SOCBrain()

result = brain.analyze_incident(
    prompt="Phishing email investigation: suspicious link clicked",
    context={
        "sender": "ceo@examp1e.com",
        "subject": "Urgent: Wire Transfer Required",
        "clicked_link": "http://evil-domain.com/login"
    }
)

print(result["raw_analysis"])
print(f"Severity: {result['severity']}")
print(f"IOCs: {result['iocs']}")
print(f"Cost: ₹{result['metadata']['total_tokens'] * 0.0001:.2f}")
```

---

## Common Use Cases

### 1. Phishing Email Analysis

```bash
curl -X POST http://localhost:8000/analyze \
  -F 'prompt=Analyze this phishing email screenshot' \
  -F 'file=@screenshot.png'
```

### 2. PCAP Investigation

```bash
curl -X POST http://localhost:8000/analyze \
  -F 'prompt=Extract IOCs and detect C2 beaconing' \
  -F 'file=@capture.pcap'
```

### 3. EDR Alert Triage

```python
alert = {
    "alert_name": "Mimikatz Detected",
    "host": "DC-01",
    "process": "lsass.exe",
    "user": "SYSTEM"
}

result = brain.triage_alert(alert)
print(result["raw_analysis"])
```

### 4. Run Pre-built Playbook

```python
incident = {
    "email_from": "attacker@evil.com",
    "email_subject": "Invoice Overdue",
    "attachments": ["invoice.pdf.exe"]
}

result = brain.run_playbook("phishing_triage", incident)
```

---

## Check Your Stats

```bash
curl http://localhost:8000/stats
```

Returns:
```json
{
  "total_analyses": 15,
  "total_tokens": 45230,
  "total_cost_usd": 0.047,
  "total_cost_inr": 3.90,
  "avg_response_time": 8.3,
  "avg_cost_per_analysis_inr": 0.26
}
```

---

## Available Playbooks

List all:
```bash
curl http://localhost:8000/playbooks
```

35 built-in playbooks including:
- `phishing_triage` - Email phishing investigation
- `ransomware_user_clicked` - Ransomware IR workflow
- `edr_process_tree` - Process tree analysis
- `lateral_movement_windows` - Detect SMB/RDP/WMI lateral movement
- `credential_dumping` - Mimikatz/LSASS dumps
- `c2_beaconing` - Command and control detection
- `lockbit_ransomware` - LockBit specific playbook
- `akira_ransomware` - Akira ransomware playbook
- `cloud_iam_abuse` - AWS/Azure/GCP IAM issues
- ... and 26 more

Full list: See [PLAYBOOKS.md](PLAYBOOKS.md)

---

## API Endpoints

- `GET /health` - Health check
- `GET /playbooks` - List available playbooks
- `GET /stats` - Usage statistics
- `POST /analyze` - Analyze (multipart: text + optional file)
- `POST /analyze_json` - Analyze (JSON body)
- `POST /playbooks/{playbook_id}/run` - Execute playbook

---

## Cost Example

**Typical Investigation:**
- Prompt: ~5K tokens
- Response: ~3K tokens
- **Cost: ₹0.65-0.85 per investigation**

**10,000 investigations/month:**
- Total: ~₹8,500/month
- Comparable analyst cost: ~₹80L-120L/year (3-5 L2/L3 FTE)

---

## Next Steps

1. **Read Documentation**
   - [ARCHITECTURE.md](ARCHITECTURE.md) - System design
   - [PLAYBOOKS.md](PLAYBOOKS.md) - All 35 playbooks
   - [DEPLOYMENT.md](DEPLOYMENT.md) - Production deployment

2. **Integrate with Your Stack**
   - Splunk alert actions
   - Microsoft Sentinel playbooks
   - Slack bot
   - Email parser

3. **Customize**
   - Add your own playbooks
   - Tune system prompt
   - Add authentication
   - Implement queueing for scale

4. **Deploy**
   - Docker
   - Kubernetes
   - Cloud Run / ECS / ACI
   - Behind NGINX/Traefik

---

## Common Issues

**"GEMINI_API_KEY not found"**
→ `export GEMINI_API_KEY=your_key`

**PCAP parsing fails**
→ `pip install dpkt`

**Slow responses**
→ Normal, Gemini processes large context. Typical: 5-15s

**Rate limits**
→ Gemini free tier has limits. Consider paid tier for production.

---

## Support

Questions or issues?
- Read docs: [ARCHITECTURE.md](ARCHITECTURE.md), [PLAYBOOKS.md](PLAYBOOKS.md), [DEPLOYMENT.md](DEPLOYMENT.md)
- Gemini API Docs: https://ai.google.dev/docs
