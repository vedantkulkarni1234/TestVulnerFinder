# SOC-EATER v2 Architecture

## Overview

SOC-EATER v2 is a production-ready SOC automation platform that leverages Google's Gemini 1.5 Flash model to deliver enterprise-grade security incident analysis at unprecedented speed and cost-efficiency.

## Core Components

### 1. SOC Brain (`soc_brain.py`)

The intelligence core of the system. Handles:

- **Gemini 1.5 Flash Integration**: Direct API integration with Google's fastest production model
- **Multimodal Analysis**: Text, images (screenshots), and binary files (PCAP)
- **Structured Output Parsing**: Extracts severity, IOCs, MITRE techniques from AI responses
- **Cost Tracking**: Real-time usage and cost metrics
- **Playbook Execution**: YAML-based investigation workflows

**Key Methods:**
- `analyze_incident()`: Main entry point for all analyses
- `analyze_screenshot()`: OCR and visual threat analysis
- `analyze_pcap()`: Network traffic investigation
- `analyze_log()`: Log file analysis
- `triage_alert()`: True/false positive determination
- `run_playbook()`: Execute pre-defined investigation workflows

### 2. FastAPI + Gradio Server (`main.py`)

Dual interface architecture:

- **REST API** (`/analyze`, `/playbooks`, `/stats`): For programmatic integration with SIEM/SOAR
- **Gradio UI** (`/`): Web interface for manual investigations

Handles:
- File upload processing (images, PCAP)
- Multipart form data
- CORS and request validation
- Automatic PCAP summarization before LLM analysis

### 3. PCAP Parser (`utils/pcap_parser.py`)

Lightweight network traffic analyzer:

- Extracts: IPs, ports, protocols, DNS queries, HTTP requests
- Identifies: External IPs, suspicious ports, high-volume connections
- Generates: Text summaries optimized for LLM consumption
- Uses `dpkt` library for packet parsing

### 4. Playbook System (`playbooks/*.yaml`)

35 pre-built investigation templates covering:

**Malware & Threats:**
- Phishing triage
- Ransomware (LockBit, Akira)
- QakBot detection
- Cryptomining
- Fileless malware

**Attack Techniques:**
- Lateral movement
- Privilege escalation
- Credential dumping
- Data exfiltration
- C2 beaconing

**Specialized:**
- Cloud IAM abuse
- Container breakout
- Supply chain attacks
- APT campaigns
- Business email compromise

## Data Flow

```
User Input (Text/Image/PCAP)
    ↓
FastAPI Endpoint
    ↓
[File Processing]
    ├─ Image → PIL → Gemini multimodal
    ├─ PCAP → Parser → Text summary
    └─ Text → Direct prompt
    ↓
SOC Brain
    ├─ System Prompt Injection
    ├─ Playbook Integration (optional)
    └─ Gemini 1.5 Flash API Call
    ↓
Response Processing
    ├─ Parse structured fields (severity, IOCs)
    ├─ Extract MITRE techniques
    └─ Calculate costs
    ↓
JSON Response / Gradio Display
```

## Prompt Engineering

The system uses a comprehensive system prompt that enforces structured output:

1. **Executive Summary**: 2-3 sentences for management
2. **Severity Assessment**: CRITICAL/HIGH/MEDIUM/LOW + confidence
3. **MITRE Mapping**: Full ATT&CK coverage
4. **Investigation Findings**: Detailed analysis
5. **IOCs**: IPs, domains, hashes, URLs, emails
6. **Blast Radius**: Affected systems and data
7. **Root Cause**: Initial vector analysis
8. **Containment**: Immediate action steps
9. **Detection Queries**: Splunk, Sentinel (KQL), Elastic
10. **Jira Ticket**: Ready-to-paste incident report

## Cost Model

**Gemini 1.5 Flash Pricing (2025):**
- Input: $0.00035 per 1K tokens
- Output: $0.00105 per 1K tokens

**Typical Investigation:**
- Prompt: ~5K tokens
- Response: ~3K tokens
- Total Cost: **~₹0.65-0.85 per investigation**

**At Scale:**
- 10,000 investigations/month: **~₹8,500/month**
- Comparable analyst cost: **~₹80L-120L/year** (3-5 L2/L3 FTE)

## Performance Characteristics

- **Response Time**: 3-15 seconds (typical)
- **Concurrency**: Limited by FastAPI workers and Gemini API rate limits
- **Context Window**: 1M tokens (Gemini 1.5 Flash)
- **Max PCAP Size**: ~4000 packets (configurable)

## Security Considerations

1. **API Key Management**: Environment variables only, never hardcoded
2. **Input Validation**: FastAPI automatic validation
3. **File Upload Limits**: Configured at server level
4. **No Data Retention**: Incidents not stored by default (add DB if needed)
5. **Multimodal Safety**: Gemini built-in content filters

## Extensibility

### Adding New Playbooks

Create `playbooks/my_playbook.yaml`:

```yaml
name: My Custom Playbook
id: my_custom_playbook
description: Description here
tags: [tag1, tag2]
inputs: [input1, input2]
steps:
  - step_1
  - step_2
```

### Adding New Analyzers

Extend `SOCBrain` class:

```python
def analyze_custom(self, data: Any) -> Dict[str, Any]:
    prompt = f"Analyze this: {data}"
    return self.analyze_incident(prompt)
```

### Integrations

**SIEM/SOAR:**
```python
import requests

result = requests.post('http://localhost:8000/analyze', 
    data={'prompt': alert_text})
```

**Slack Bot:**
```python
# On @mention, call API and post result
```

**Email Parser:**
```python
# Parse phishing reports, submit to /analyze
```

## Production Deployment

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENV GEMINI_API_KEY=""
CMD ["python", "soc_eater_v2/main.py"]
```

### Environment Variables

- `GEMINI_API_KEY`: Required
- `HOST`: Default 0.0.0.0
- `PORT`: Default 8000
- `LOG_LEVEL`: Default info

### Scaling

- **Horizontal**: Multiple FastAPI workers behind load balancer
- **Rate Limits**: Gemini API has rate limits; implement queuing for high volume
- **Caching**: Consider caching identical prompts (optional)

## Monitoring

Track these metrics:
- Total investigations
- Average response time
- Cost per investigation
- Error rate
- Playbook usage distribution

Access via `GET /stats` endpoint.

## Limitations

1. **No Memory**: Each investigation is stateless (no conversation history)
2. **PCAP Parsing**: Simplified; not full forensic-grade
3. **OCR**: Relies on Gemini's built-in vision; may miss text in complex images
4. **Rate Limits**: Gemini API enforces rate limiting
5. **Hallucinations**: Like all LLMs, may occasionally generate incorrect information

## Roadmap

- [ ] Add vector database for investigation memory
- [ ] Implement full PCAP forensics
- [ ] Multi-turn investigation conversations
- [ ] Auto-escalation to L3 based on severity
- [ ] Integration with major SIEM platforms (Splunk, Sentinel, Elastic)
- [ ] Report export (PDF, CSV)
- [ ] Audit logging and compliance
- [ ] Fine-tuning on custom security data

## License

MIT (or your preferred license)
