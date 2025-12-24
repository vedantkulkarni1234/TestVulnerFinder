"""
SOC-EATER v2 - Core Brain Module
Powered by Gemini 1.5 Flash for autonomous security operations
"""

import os
import json
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

import yaml


class SOCBrain:
    """
    The core AI brain for autonomous SOC operations.
    Uses Gemini 1.5 Flash for ultra-fast, cost-effective incident analysis.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the SOC Brain with Gemini 1.5 Flash"""
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")
        
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")
        
        genai.configure(api_key=self.api_key)
        
        # Use Gemini 1.5 Flash - fastest and most cost-effective
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Load playbooks
        self.playbooks = self._load_playbooks()
        
        # Statistics
        self.stats = {
            "total_analyses": 0,
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "avg_response_time": 0.0
        }
    
    def _load_playbooks(self) -> Dict[str, Any]:
        """Load all YAML playbooks from the playbooks directory"""
        playbooks = {}
        playbook_dir = Path(__file__).parent / "playbooks"
        
        if not playbook_dir.exists():
            return {}
        
        for playbook_file in playbook_dir.glob("*.yaml"):
            try:
                with open(playbook_file) as f:
                    playbook_data = yaml.safe_load(f)
                    playbooks[playbook_file.stem] = playbook_data
            except Exception as e:
                print(f"Failed to load playbook {playbook_file}: {e}")
        
        return playbooks
    
    def analyze_incident(
        self,
        prompt: str,
        context: Optional[Dict] = None,
        images: Optional[List[Any]] = None,
        files: Optional[List[bytes]] = None
    ) -> Dict[str, Any]:
        """
        Main entry point for incident analysis.
        Handles text, images, files, and multimodal inputs.
        
        Returns a complete investigation report.
        """
        start_time = time.time()
        
        # Build the comprehensive analysis prompt
        system_prompt = self._build_system_prompt()
        full_prompt = f"{system_prompt}\n\n{prompt}"
        
        # Add context if provided
        if context:
            full_prompt += f"\n\nAdditional Context:\n{json.dumps(context, indent=2)}"
        
        # Prepare multimodal inputs
        inputs = [full_prompt]
        
        if images:
            inputs.extend(images)
        
        # Generate response
        try:
            response = self.model.generate_content(inputs)
            analysis = response.text
            
            # Extract structured data from response
            result = self._parse_analysis(analysis)
            
            # Add metadata
            elapsed = time.time() - start_time
            result["metadata"] = {
                "timestamp": datetime.utcnow().isoformat(),
                "model": "gemini-1.5-flash",
                "response_time_seconds": round(elapsed, 2),
                "prompt_tokens": response.usage_metadata.prompt_token_count if hasattr(response, 'usage_metadata') else 0,
                "completion_tokens": response.usage_metadata.candidates_token_count if hasattr(response, 'usage_metadata') else 0,
                "total_tokens": response.usage_metadata.total_token_count if hasattr(response, 'usage_metadata') else 0
            }
            
            # Update stats
            self._update_stats(result["metadata"])
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _build_system_prompt(self) -> str:
        """Build the comprehensive system prompt for SOC analysis"""
        return """You are an elite SOC Analyst AI with 15+ years of cybersecurity experience.
You specialize in rapid incident triage, threat hunting, and incident response.

Your mission: Analyze any security alert, log, PCAP, screenshot, or prompt and provide a COMPLETE investigation report.

You MUST structure your response in the following format:

## EXECUTIVE SUMMARY
[2-3 sentence summary suitable for CISO/management]

## SEVERITY ASSESSMENT
- Severity: [CRITICAL|HIGH|MEDIUM|LOW|INFO]
- Confidence: [HIGH|MEDIUM|LOW]
- Urgency: [IMMEDIATE|HIGH|MEDIUM|LOW]

## INCIDENT CLASSIFICATION
- Category: [e.g., Phishing, Malware, Lateral Movement, Data Exfiltration, etc.]
- MITRE ATT&CK Tactics: [List all applicable tactics]
- MITRE ATT&CK Techniques: [List all applicable techniques with IDs]

## INVESTIGATION FINDINGS
[Detailed analysis of what happened, when, how, and why]

## INDICATORS OF COMPROMISE (IOCs)
- IP Addresses: [list]
- Domains: [list]
- File Hashes: [list]
- URLs: [list]
- Email Addresses: [list]
- Other: [list]

## BLAST RADIUS
- Affected Systems: [list]
- Affected Users: [list]
- Data at Risk: [description]
- Potential Impact: [description]

## ROOT CAUSE
[What was the initial attack vector and how did the attacker gain access]

## CONTAINMENT STEPS (Immediate)
1. [Step 1]
2. [Step 2]
3. [Step 3]

## REMEDIATION RECOMMENDATIONS
1. [Step 1]
2. [Step 2]
3. [Step 3]

## DETECTION QUERIES
### Splunk
```spl
[Splunk query to detect this activity]
```

### Microsoft Sentinel (KQL)
```kql
[KQL query to detect this activity]
```

### Elastic
```json
[Elastic query to detect this activity]
```

## THREAT INTELLIGENCE
- Known Threat Actor: [if applicable]
- Campaign: [if applicable]
- TTPs: [description]
- Similar Incidents: [references]

## RECOMMENDED ACTIONS FOR MANAGEMENT
1. [Action 1]
2. [Action 2]
3. [Action 3]

## JIRA TICKET DRAFT
**Title:** [Concise incident title]
**Priority:** [P0/P1/P2/P3]
**Description:** [Full description ready to paste into Jira]

---

Be thorough, accurate, and actionable. Your analysis will be used directly by security teams."""
    
    def _parse_analysis(self, analysis_text: str) -> Dict[str, Any]:
        """Parse the structured analysis text into a dictionary"""
        
        # Extract key sections using simple parsing
        result = {
            "raw_analysis": analysis_text,
            "status": "completed"
        }
        
        # Try to extract severity
        if "Severity:" in analysis_text:
            for line in analysis_text.split("\n"):
                if "Severity:" in line:
                    severity = line.split("Severity:")[-1].strip()
                    result["severity"] = severity.split()[0] if severity else "UNKNOWN"
                    break
        
        # Extract MITRE ATT&CK techniques
        mitre_techniques = []
        if "MITRE ATT&CK Techniques:" in analysis_text:
            start = analysis_text.find("MITRE ATT&CK Techniques:")
            end = analysis_text.find("\n\n", start)
            if end > start:
                techniques_section = analysis_text[start:end]
                # Simple extraction - look for T#### patterns
                import re
                mitre_techniques = re.findall(r'T\d{4}(?:\.\d{3})?', techniques_section)
        
        result["mitre_techniques"] = mitre_techniques
        
        # Extract IOCs
        iocs = {
            "ips": [],
            "domains": [],
            "hashes": [],
            "urls": [],
            "emails": []
        }
        
        if "INDICATORS OF COMPROMISE" in analysis_text:
            import re
            
            # Extract IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            iocs["ips"] = list(set(re.findall(ip_pattern, analysis_text)))
            
            # Extract domains (simple pattern)
            domain_pattern = r'\b[a-z0-9\-]+\.[a-z]{2,}\b'
            iocs["domains"] = list(set(re.findall(domain_pattern, analysis_text.lower())))
            
            # Extract hashes (MD5, SHA1, SHA256)
            hash_pattern = r'\b[a-f0-9]{32,64}\b'
            iocs["hashes"] = list(set(re.findall(hash_pattern, analysis_text.lower())))
        
        result["iocs"] = iocs
        
        return result
    
    def _update_stats(self, metadata: Dict):
        """Update internal statistics"""
        self.stats["total_analyses"] += 1
        self.stats["total_tokens"] += metadata.get("total_tokens", 0)
        
        # Gemini 1.5 Flash pricing: $0.00035 per 1K tokens (input), $0.00105 per 1K tokens (output)
        prompt_tokens = metadata.get("prompt_tokens", 0)
        completion_tokens = metadata.get("completion_tokens", 0)
        
        cost = (prompt_tokens / 1000 * 0.00035) + (completion_tokens / 1000 * 0.00105)
        self.stats["total_cost_usd"] += cost
        
        # Update avg response time
        current_avg = self.stats["avg_response_time"]
        new_time = metadata.get("response_time_seconds", 0)
        self.stats["avg_response_time"] = (current_avg * (self.stats["total_analyses"] - 1) + new_time) / self.stats["total_analyses"]
    
    def get_playbook(self, playbook_name: str) -> Optional[Dict]:
        """Get a specific playbook by name"""
        return self.playbooks.get(playbook_name)
    
    def list_playbooks(self) -> List[str]:
        """List all available playbooks"""
        return list(self.playbooks.keys())
    
    def run_playbook(self, playbook_name: str, incident_data: Dict) -> Dict[str, Any]:
        """Execute a specific playbook with incident data"""
        playbook = self.get_playbook(playbook_name)
        
        if not playbook:
            return {"error": f"Playbook '{playbook_name}' not found"}
        
        # Build prompt from playbook
        prompt = f"""Execute the following security playbook:

Playbook: {playbook.get('name', playbook_name)}
Description: {playbook.get('description', '')}

Incident Data:
{json.dumps(incident_data, indent=2)}

Follow these steps:
{yaml.dump(playbook.get('steps', []), default_flow_style=False)}

Provide a complete analysis following the standard SOC report format."""
        
        return self.analyze_incident(prompt, context=incident_data)
    
    def analyze_pcap(self, pcap_data: bytes, description: str = "") -> Dict[str, Any]:
        """Analyze PCAP data (simplified - would need full parser in production)"""
        
        prompt = f"""Analyze the following network traffic capture (PCAP):

Description: {description}

Provide a complete security analysis including:
- Suspicious connections
- Data exfiltration attempts
- Malware C2 communications
- Lateral movement indicators
- All IOCs (IPs, domains, protocols)
- Attack timeline
- MITRE ATT&CK mapping
"""
        
        return self.analyze_incident(prompt)
    
    def analyze_screenshot(self, image_path: str, description: str = "") -> Dict[str, Any]:
        """Analyze a screenshot (phishing email, alert, etc.)"""
        
        try:
            from PIL import Image
        except ImportError:
            return {"error": "pillow package not installed. Run: pip install pillow"}

        try:
            image = Image.open(image_path).convert("RGB")
        except Exception as e:
            return {"error": f"Failed to load image: {str(e)}"}
        
        prompt = f"""Analyze this security-related screenshot.

Context: {description}

Extract and analyze:
- All text content (use OCR if needed)
- Suspicious indicators
- URLs, email addresses, phone numbers
- Social engineering tactics
- Brand impersonation attempts
- Malicious file attachments
- Technical headers (if email)
- Complete threat assessment

Provide full SOC analysis report."""
        
        return self.analyze_incident(prompt, images=[image])
    
    def analyze_log(self, log_data: str, log_type: str = "unknown") -> Dict[str, Any]:
        """Analyze security logs (Syslog, Windows Event, EDR, etc.)"""
        
        prompt = f"""Analyze the following {log_type} security log data:

```
{log_data}
```

Provide complete security analysis including anomaly detection, threat indicators, and investigation recommendations."""
        
        return self.analyze_incident(prompt)
    
    def triage_alert(self, alert_data: Dict) -> Dict[str, Any]:
        """Triage a security alert and determine if it's a true positive"""
        
        prompt = f"""Triage this security alert:

{json.dumps(alert_data, indent=2)}

Determine:
1. Is this a TRUE POSITIVE, FALSE POSITIVE, or INDETERMINATE?
2. What is the severity and urgency?
3. What immediate actions should be taken?
4. Should this be escalated to L2/L3?

Provide complete triage assessment."""
        
        return self.analyze_incident(prompt, context=alert_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        stats = self.stats.copy()
        stats["total_cost_inr"] = round(stats["total_cost_usd"] * 83, 2)  # Approximate conversion
        stats["avg_cost_per_analysis_inr"] = round(stats["total_cost_inr"] / max(stats["total_analyses"], 1), 2)
        return stats
