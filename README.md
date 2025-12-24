# SOC-EATER v2

**Gemini 1.5 Flash-powered SOC automation platform** — FastAPI + Gradio stack for rapid alert triage, investigation summarization, IOC extraction, MITRE ATT&CK mapping, and detection query generation.

🎯 **One prompt → Full L1/L2/L3 investigation in <15 seconds at ~₹0.65-0.85 per incident**

---

## Features

✅ **35 Pre-built Playbooks** — Phishing, ransomware, lateral movement, privilege escalation, APT campaigns, cloud IAM abuse, and more  
✅ **Multimodal Analysis** — Text, screenshots, PCAP files  
✅ **Gemini 1.5 Flash** — 1M token context, fastest & cheapest production model  
✅ **MITRE ATT&CK Mapping** — Automatic technique identification  
✅ **IOC Extraction** — IPs, domains, hashes, URLs, emails  
✅ **Detection Queries** — Splunk SPL, Sentinel KQL, Elastic DSL  
✅ **FastAPI + Gradio** — REST API + Web UI  
✅ **Cost Tracking** — Real-time usage and cost metrics  

---

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Get Gemini API key (free): https://ai.google.dev
export GEMINI_API_KEY=your_key_here

# 3. Run
python soc_eater_v2/main.py
```

Open:
- **Web UI:** http://localhost:8000/
- **API Docs:** http://localhost:8000/docs

📖 **Full Guide:** [QUICKSTART.md](QUICKSTART.md)

---

## API Examples

### Analyze Text Alert

```bash
curl -X POST http://localhost:8000/analyze_json \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Suspicious PowerShell execution detected: powershell.exe -encodedCommand ...",
    "context": {"host": "WS-001", "user": "john.doe"}
  }'
```

### Analyze Screenshot

```bash
curl -X POST http://localhost:8000/analyze \
  -F 'prompt=Analyze this phishing email screenshot' \
  -F 'file=@screenshot.png'
```

### Analyze PCAP

```bash
curl -X POST http://localhost:8000/analyze \
  -F 'prompt=Extract IOCs and detect C2 beaconing' \
  -F 'file=@capture.pcap'
```

### Run Playbook

```bash
curl -X POST http://localhost:8000/playbooks/phishing_triage/run \
  -H "Content-Type: application/json" \
  -d '{
    "incident_data": {
      "email_from": "ceo@examp1e.com",
      "subject": "Urgent: Wire Transfer",
      "attachments": ["invoice.pdf.exe"]
    }
  }'
```

---

## API Endpoints

- `GET /health` — Health check
- `GET /playbooks` — List all 35 playbooks
- `GET /stats` — Usage statistics and costs
- `POST /analyze` — Analyze with multipart form (text + optional file)
- `POST /analyze_json` — Analyze with JSON body
- `POST /playbooks/{playbook_id}/run` — Execute specific playbook

Full API docs: http://localhost:8000/docs

---

## 35 Built-in Playbooks

**Malware & Threats:**
- Phishing triage • EDR process tree • PCAP IOC extraction • Ransomware (user clicked)
- LockBit ransomware • Akira ransomware • QakBot detection • Malware detonation
- Cryptomining • Fileless malware • Malicious Office macro

**Attack Techniques:**
- Lateral movement (Windows) • Privilege escalation • Credential dumping
- Data exfiltration • C2 beaconing • DNS tunneling • Persistence (registry/tasks)
- PowerShell suspicious • Brute force attacks

**Specialized:**
- Insider threat • Cloud IAM abuse (AWS/Azure/GCP) • Supply chain attack
- APT campaign • Container breakout • Shadow IT • Business email compromise
- Zero-day exploit • DDoS attack • VPN anomaly • Compromised account
- Rogue admin • Suspicious RDP session • PhantomL0rd backdoor • Web attacks (SQLi/XSS)

📖 **Full Details:** [PLAYBOOKS.md](PLAYBOOKS.md)

---

## Documentation

- [**QUICKSTART.md**](QUICKSTART.md) — Get started in 60 seconds
- [**ARCHITECTURE.md**](ARCHITECTURE.md) — System design & internals
- [**PLAYBOOKS.md**](PLAYBOOKS.md) — All 35 playbooks documented
- [**DEPLOYMENT.md**](DEPLOYMENT.md) — Docker, K8s, Cloud Run, production guides

---

## Cost Model

**Gemini 1.5 Flash (2025 pricing):**
- Input: $0.00035 per 1K tokens
- Output: $0.00105 per 1K tokens

**Typical Investigation:**
- ~8K total tokens → **~₹0.65-0.85 per investigation**

**At Scale:**
- 10,000 investigations/month → **~₹8,500/month**
- Comparable analyst cost → **₹80L-120L/year** (3-5 FTE)

---

## Production Deployment

### Docker

```bash
docker build -t soc-eater-v2 .
docker run -d -p 8000:8000 -e GEMINI_API_KEY=your_key soc-eater-v2
```

### Kubernetes / Cloud

See [DEPLOYMENT.md](DEPLOYMENT.md) for:
- Google Cloud Run
- AWS ECS/Fargate
- Azure Container Instances
- Kubernetes manifests
- NGINX/Traefik reverse proxy
- Security best practices

---

## Integrations

- **Splunk** — Alert actions
- **Microsoft Sentinel** — Logic App playbooks
- **Slack** — Bot integration
- **Email** — Phishing report parser
- **SIEM/SOAR** — REST API

See [DEPLOYMENT.md](DEPLOYMENT.md) for examples.

---

## Tech Stack

- **Backend:** Python 3.11+ • FastAPI • Uvicorn
- **AI:** Google Gemini 1.5 Flash (1M token context)
- **UI:** Gradio
- **Parsing:** dpkt (PCAP) • Pillow (images) • PyYAML (playbooks)
- **Deployment:** Docker • K8s • Cloud native

---

## Notes

- Gemini 1.5 Flash is production-ready, fast, and cost-effective
- PCAP parsing is lightweight (summary for LLM, not full forensics)
- Stateless by default (no incident storage; add DB if needed)
- Rate limits apply (Gemini API free tier)

---

## License

MIT (or your preferred license)

---

## Support

- **Documentation:** This README + [ARCHITECTURE.md](ARCHITECTURE.md) + [PLAYBOOKS.md](PLAYBOOKS.md) + [DEPLOYMENT.md](DEPLOYMENT.md)
- **Gemini API:** https://ai.google.dev/docs
- **Issues:** [Your repo issues page]

---

**Built for security teams who want speed, accuracy, and cost-efficiency. One prompt → Full investigation → Done.** 🎯
