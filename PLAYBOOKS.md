# SOC-EATER v2 Playbooks

Complete list of 27 built-in automated investigation playbooks.

## Usage

Via API:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Run the phishing_triage playbook",
    "context_json": "{\"email_from\": \"attacker@evil.com\", \"subject\": \"Urgent: Reset your password\"}"
  }'
```

Via Python:
```python
from soc_eater_v2.soc_brain import SOCBrain

brain = SOCBrain()
result = brain.run_playbook("phishing_triage", {
    "email_from": "attacker@evil.com",
    "subject": "Urgent: Reset your password",
    "body": "Click here to verify..."
})
```

---

## 1. Phishing Triage
**ID:** `phishing_triage`  
**Tags:** phishing, email, bec, malware

End-to-end phishing email triage, IOC extraction, detonation guidance, and user response recommendations.

**Steps:**
- Identify sender reputation
- Extract URLs/domains/IPs
- Extract attachment metadata and hashes
- Assess social engineering tactics
- Recommend safe detonation steps
- Determine user impact and scope
- Propose blocking actions
- Draft user reply and security notice

---

## 2. EDR Process Tree Investigation
**ID:** `edr_process_tree`  
**Tags:** edr, endpoint, malware, execution

Investigate an EDR alert by reconstructing process lineage, parent/child relationships, and execution context.

**Steps:**
- Reconstruct process tree
- Identify LOLBins and suspicious args
- Map to MITRE techniques
- Determine initial vector
- Scope similar events across fleet
- Recommend containment/isolation actions
- Recommend eradication steps

---

## 3. PCAP IOC Extraction
**ID:** `pcap_ioc_extraction`  
**Tags:** pcap, network, ioc, c2

Extract all IOCs from a PCAP, infer attack stages, and produce hunt queries.

**Steps:**
- Extract external IPs/domains/URLs
- Identify DNS and HTTP indicators
- Identify suspicious ports and protocols
- Infer beaconing or exfiltration
- Map to MITRE network techniques
- Produce detection queries

---

## 4. Ransomware User Clicked
**ID:** `ransomware_user_clicked`  
**Tags:** ransomware, incident_response, containment

Rapid ransomware incident response workflow from initial click through containment and recovery.

**Steps:**
- Confirm encryption and scope
- Identify patient zero
- Isolate hosts and disable accounts
- Block IOCs at edge and EDR
- Collect artifacts for forensics
- Map to MITRE ransomware chain
- Recommend restoration and hardening
- Generate executive and legal-ready summary

---

## 5. Lateral Movement - Windows
**ID:** `lateral_movement_windows`  
**Tags:** lateral_movement, windows, smb, rdp, wmi

Detect and investigate lateral movement using SMB, RDP, WMI, WinRM, PsExec.

**Steps:**
- Identify remote execution events
- Correlate authentication and logon types
- Find admin share access and PsExec service
- Map to MITRE lateral movement
- Scope impacted hosts and accounts
- Recommend password reset and KrbTGT rotation if needed

---

## 6. Suspicious PowerShell Execution
**ID:** `powershell_suspicious`  
**Tags:** powershell, lolbin, execution

Investigate PowerShell with obfuscation, encoded commands, or download cradles.

**Steps:**
- Decode EncodedCommand if present
- Extract URLs and payload paths
- Identify obfuscation patterns
- Map to MITRE PowerShell techniques
- Generate hunt queries for similar commands
- Recommend Constrained Language Mode and logging

---

## 7. Privilege Escalation - Windows
**ID:** `privilege_escalation_windows`  
**Tags:** privilege_escalation, windows

Investigate privilege escalation attempts (UAC bypass, token manipulation, vulnerable drivers).

**Steps:**
- Identify privileged logons and token events
- Check UAC bypass indicators
- Look for suspicious driver loads
- Correlate with process injection or credential access
- Recommend patch and remove vulnerable software

---

## 8. Persistence - Registry/Tasks
**ID:** `persistence_registry_tasks`  
**Tags:** persistence, windows

Detect persistence via registry run keys, scheduled tasks, services, and startup folders.

**Steps:**
- Enumerate run keys and startup entries
- Inspect scheduled tasks for suspicious actions
- Check new or modified services
- Map to MITRE persistence techniques
- Recommend cleanup and baselining

---

## 9. Credential Dumping
**ID:** `credential_dumping`  
**Tags:** credential_access, mimikatz, lsass

Detect and investigate credential theft via Mimikatz, LSASS dumps, DCSync, etc.

**Steps:**
- Detect LSASS process access
- Identify Mimikatz or credential tools
- Check for DCSync replication requests
- Map to MITRE credential access
- Recommend immediate password rotation
- Recommend KrbTGT reset if Golden Ticket suspected

---

## 10. Data Exfiltration Detection
**ID:** `data_exfiltration`  
**Tags:** exfiltration, dlp, cloud

Identify unusual data transfers via cloud upload, USB, email, FTP, etc.

**Steps:**
- Detect large file uploads to public cloud
- Identify USB usage and file copies
- Check email attachments with sensitive data
- Analyze FTP/SFTP/SCP transfers
- Map to MITRE exfiltration techniques
- Recommend DLP tuning and egress filtering

---

## 11. C2 Beaconing Detection
**ID:** `c2_beaconing`  
**Tags:** c2, beaconing, cobalt_strike

Identify periodic beaconing patterns indicative of C2 communication.

**Steps:**
- Analyze periodic HTTP/HTTPS requests
- Detect DNS tunneling and long domain queries
- Identify Cobalt Strike Malleable C2 patterns
- Map to MITRE C2 techniques
- Recommend blocking C2 domains and IPs
- Provide threat hunt queries

---

## 12. Web Attack - SQLi/XSS
**ID:** `web_attack_sqli_xss`  
**Tags:** web, sqli, xss, waf

Investigate SQLi, XSS, command injection, and other web exploits.

**Steps:**
- Identify SQL injection patterns
- Detect XSS payloads in requests
- Check for command injection and RCE
- Map to MITRE web exploitation
- Recommend WAF tuning and input validation
- Recommend app patching and code review

---

## 13. Insider Threat Investigation
**ID:** `insider_threat`  
**Tags:** insider, ueba, anomaly

Investigate suspicious behavior by privileged users or terminated employees.

**Steps:**
- Baseline normal user behavior
- Detect unusual access patterns
- Identify off-hours or unauthorized locations
- Check data access and downloads
- Correlate with HR termination or disciplinary actions
- Recommend account monitoring and controls

---

## 14. Cloud IAM Abuse
**ID:** `cloud_iam_abuse`  
**Tags:** cloud, aws, azure, gcp, iam

Detect privilege escalation, credential exposure, and unauthorized access in cloud IAM.

**Steps:**
- Identify new user or role creation
- Detect privilege escalation via policy changes
- Check for exposed access keys or credentials
- Analyze cross-account AssumeRole activity
- Map to MITRE cloud techniques
- Recommend IAM hardening and MFA enforcement

---

## 15. Supply Chain Attack
**ID:** `supply_chain_attack`  
**Tags:** supply_chain, software, vendor

Investigate malicious updates, compromised vendor tools, or trojanized software.

**Steps:**
- Identify suspicious software or update source
- Verify code signing certificates
- Check for embedded backdoors or implants
- Scope distribution across enterprise
- Map to MITRE supply chain compromise
- Recommend vendor review and rollback

---

## 16. APT Campaign Investigation
**ID:** `apt_campaign`  
**Tags:** apt, nation_state, advanced

Full investigation for advanced persistent threat campaigns with multiple TTPs.

**Steps:**
- Aggregate IOCs across sources
- Map full attack chain to MITRE
- Correlate with known APT groups
- Analyze TTPs and attribution
- Scope full enterprise impact
- Recommend long-term hardening and monitoring
- Produce executive and board-ready brief

---

## 17. Malware Detonation
**ID:** `malware_detonation`  
**Tags:** malware, sandbox, dynamic_analysis

Guide safe malware detonation in sandbox and extract behavioral IOCs.

**Steps:**
- Recommend sandbox environment
- Extract network IOCs from detonation
- Identify file system and registry modifications
- Detect process injection and evasion
- Map to MITRE malware techniques
- Generate YARA or Snort rules

---

## 18. Brute Force Attack
**ID:** `brute_force_attack`  
**Tags:** brute_force, authentication, rdp, ssh

Detect and respond to password brute forcing or credential stuffing.

**Steps:**
- Identify high-volume failed logins
- Detect credential stuffing patterns
- Correlate with known attacker IPs
- Map to MITRE credential access
- Recommend account lockout and IP blocking
- Recommend MFA and rate limiting

---

## 19. VPN Anomaly Detection
**ID:** `vpn_anomaly`  
**Tags:** vpn, remote_access, geo_anomaly

Detect impossible travel, compromised VPN credentials, or unauthorized access.

**Steps:**
- Detect impossible travel scenarios
- Identify unusual source countries
- Check concurrent logins from multiple locations
- Correlate with credential theft indicators
- Recommend account suspension and investigation
- Recommend stronger VPN authentication

---

## 20. DDoS Attack
**ID:** `ddos_attack`  
**Tags:** ddos, availability, network

Identify volumetric, protocol, or application-layer DDoS attacks.

**Steps:**
- Detect abnormal traffic volume or connection rates
- Identify source IPs and attack patterns
- Classify DDoS type (volumetric, SYN flood, HTTP flood)
- Map to MITRE DoS techniques
- Recommend rate limiting and blackholing
- Recommend CDN or scrubbing center activation

---

## 21. Zero-Day Exploit
**ID:** `zero_day_exploit`  
**Tags:** zero_day, vulnerability, exploit

Investigate unknown vulnerabilities and exploitation attempts.

**Steps:**
- Identify unusual exploitation patterns
- Extract exploit payload and shellcode
- Analyze memory dumps and crash reports
- Check for patches or vendor advisories
- Map to MITRE exploitation techniques
- Recommend virtual patching and segmentation
- Coordinate with vendor and CERTs

---

## 22. DNS Tunneling
**ID:** `dns_tunneling`  
**Tags:** dns, tunneling, c2

Detect covert data exfiltration or C2 over DNS.

**Steps:**
- Detect long DNS query names
- Identify high query volume to single domain
- Check for unusual record types (TXT, NULL)
- Analyze entropy and randomness in queries
- Map to MITRE C2 and exfiltration
- Recommend DNS filtering and monitoring

---

## 23. Compromised Account
**ID:** `compromised_account`  
**Tags:** account, compromise, incident_response

Full investigation for confirmed or suspected account compromise.

**Steps:**
- Identify initial compromise vector
- Timeline all account activity since compromise
- Identify accessed resources and data
- Check for persistence and backdoors
- Scope lateral movement from account
- Recommend password reset and token revocation
- Recommend security awareness training

---

## 24. Malicious Office Macro
**ID:** `malicious_macro`  
**Tags:** macro, vba, phishing, office

Analyze weaponized Office documents with VBA macros or embedded scripts.

**Steps:**
- Extract and deobfuscate VBA macros
- Identify auto-execution methods
- Extract download URLs and payload locations
- Map to MITRE initial access and execution
- Recommend macro blocking and ASR rules
- Generate detection signatures

---

## 25. Container Breakout
**ID:** `container_breakout`  
**Tags:** container, docker, kubernetes, escape

Detect and investigate container escape or privilege escalation in Docker/K8s.

**Steps:**
- Detect privileged container execution
- Identify host file system access
- Check for exposed Docker socket
- Analyze K8s RBAC misconfigurations
- Map to MITRE container escape
- Recommend hardening and runtime security

---

## 26. Cryptomining Malware
**ID:** `cryptomining_malware`  
**Tags:** cryptomining, malware, resource_abuse

Detect unauthorized cryptocurrency miners on endpoints or servers.

**Steps:**
- Detect high CPU usage anomalies
- Identify known miner processes or pools
- Check network connections to mining pools
- Map to MITRE resource hijacking
- Recommend removal and hardening
- Recommend endpoint monitoring for recurrence

---

## 27. Shadow IT
**ID:** `shadow_it`  
**Tags:** shadow_it, cloud, saas, casb

Identify unauthorized cloud services and applications used by employees.

**Steps:**
- Identify unauthorized cloud services
- Assess data sharing and compliance risk
- Correlate with users and departments
- Map to business impact and data classification
- Recommend approved alternatives
- Recommend CASB and policy enforcement

---

## 28. Business Email Compromise
**ID:** `business_email_compromise`  
**Tags:** bec, ceo_fraud, phishing, financial

Investigate CEO fraud, wire transfer scams, and email account takeover for financial fraud.

**Steps:**
- Identify spoofed or compromised executive accounts
- Analyze email flow and unusual forwarding rules
- Detect urgent wire transfer requests
- Correlate with financial losses
- Map to MITRE social engineering
- Recommend executive protection and verification procedures
- Coordinate with finance and legal teams

---

## 29. Fileless Malware
**ID:** `fileless_malware`  
**Tags:** fileless, lolbins, memory, powershell

Detect malware that operates in memory using legitimate tools (LOLBins).

**Steps:**
- Detect suspicious LOLBin usage
- Identify process injection and reflective loading
- Analyze command-line obfuscation
- Check for persistence via WMI or registry
- Map to MITRE defense evasion
- Recommend enhanced logging and EDR coverage

---

## 30. Rogue Administrator
**ID:** `rogue_admin`  
**Tags:** privilege, admin, iam

Detect unauthorized privileged account creation or abuse.

**Steps:**
- Detect new admin accounts or group memberships
- Identify unauthorized Domain Admin activity
- Check for Golden Ticket or Silver Ticket usage
- Correlate with legitimate change control
- Map to MITRE persistence and privilege escalation
- Recommend admin account monitoring and JEA
- Recommend immediate investigation and account lockdown

---

## 31. Suspicious RDP Session
**ID:** `suspicious_rdp_session`  
**Tags:** rdp, lateral_movement, remote_access

Investigate unusual or unauthorized RDP connections.

**Steps:**
- Identify RDP connections from unusual sources
- Detect off-hours or geo-anomalous RDP
- Check for RDP brute force followed by success
- Correlate with account compromise indicators
- Map to MITRE lateral movement
- Recommend RDP hardening and network segmentation
- Recommend MFA and conditional access

---

## 32. QakBot Detection
**ID:** `qakbot_detection`  
**Tags:** qakbot, malware, botnet

Detect and respond to QakBot malware infections.

**Steps:**
- Identify QakBot initial delivery via phishing
- Detect process injection into legitimate processes
- Identify C2 beaconing to known QakBot infrastructure
- Extract IOCs from known QakBot campaigns
- Map to MITRE QakBot TTPs
- Recommend isolation and remediation
- Recommend email filtering and user awareness

---

## 33. LockBit Ransomware
**ID:** `lockbit_ransomware`  
**Tags:** lockbit, ransomware, incident_response

Detect and respond to LockBit ransomware attacks.

**Steps:**
- Identify LockBit initial access vectors
- Detect ransomware encryption patterns
- Extract IOCs from LockBit artifacts
- Identify data exfiltration before encryption
- Map to MITRE LockBit chain
- Recommend immediate containment and backup restoration
- Coordinate with legal and law enforcement

---

## 34. Akira Ransomware
**ID:** `akira_ransomware`  
**Tags:** akira, ransomware, incident_response

Detect and respond to Akira ransomware incidents including pre-encryption exfiltration.

**Steps:**
- Identify initial access vectors (VPN, RDP, or exposed services)
- Detect credential access and lateral movement
- Identify pre-encryption data exfiltration
- Extract IOCs from Akira artifacts
- Map to MITRE Akira attack chain
- Recommend immediate containment and backup restoration
- Coordinate with legal and law enforcement

---

## 35. PhantomL0rd Backdoor
**ID:** `phantomlord`  
**Tags:** backdoor, malware, c2, persistence

Investigate suspected PhantomL0rd-style backdoor behavior (persistence, C2, credential access).

**Steps:**
- Identify persistence mechanisms (services, tasks, run keys)
- Detect C2 domains/IPs and beaconing intervals
- Check for credential access or browser theft
- Scope impacted hosts and user accounts
- Map to MITRE backdoor TTPs
- Recommend isolation and full reimage if needed
- Recommend IOC blocking and hunting

---

## Creating Custom Playbooks

1. Create `playbooks/my_playbook.yaml`
2. Define structure:
```yaml
name: My Custom Investigation
id: my_custom_investigation
description: What this playbook does
tags: [tag1, tag2, tag3]
inputs: [required_input1, required_input2]
steps:
  - step_1_description
  - step_2_description
  - step_3_description
```
3. Run: `brain.run_playbook("my_custom_investigation", incident_data)`

The playbook will be automatically loaded and available via API/code.
