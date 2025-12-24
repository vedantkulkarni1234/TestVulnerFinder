# SOC-EATER v2 Desktop Application

**Standalone Desktop GUI for AI-Powered Security Operations**

---

## Overview

SOC-EATER v2 Desktop is a native, installable desktop application that provides the same powerful AI-driven SOC analysis capabilities as the web version, but without requiring a web browser or continuous internet connection for the application itself.

### Key Features

✅ **Native Desktop Experience** - Full GUI application, not a web app wrapped in Electron  
✅ **Cross-Platform** - Runs on Windows, macOS, and Linux  
✅ **Offline Capable** - No web server required, runs locally  
✅ **All Core Features** - Incident analysis, playbooks, IOC extraction, MITRE ATT&CK mapping  
✅ **Modern Dark Theme** - Professional UI designed for security operations centers  
✅ **Background Processing** - Analysis runs in worker threads for responsive UI  
✅ **File Attachments** - Support for images and PCAP files  
✅ **Export & Copy** - Export reports to files or copy to clipboard  

---

## Installation

### Prerequisites

- **Python 3.11 or higher**
- **Gemini API Key** - Get it free at https://ai.google.dev

### Option 1: Install from Source

```bash
# Clone the repository
git clone https://github.com/soc-eater/soc-eater-v2.git
cd soc-eater-v2

# Install in development mode
pip install -e .

# Set your API key (or configure in-app)
export GEMINI_API_KEY=your_api_key_here

# Run the desktop application
soc-eater-desktop
```

### Option 2: Direct Run

```bash
# Install dependencies
pip install -r requirements.txt

# Set your API key
export GEMINI_API_KEY=your_api_key_here

# Run directly
python -m soc_eater_v2.desktop_app
```

### Option 3: Create Desktop Shortcut

**Linux/macOS:**
```bash
# Create a launcher script
cat > ~/.local/bin/soc-eater-desktop << 'EOF'
#!/bin/bash
cd /path/to/soc-eater-v2
export GEMINI_API_KEY=your_api_key_here
python -m soc_eater_v2.desktop_app
EOF
chmod +x ~/.local/bin/soc-eater-desktop
```

**Windows:**
Create a batch file `soc-eater-desktop.bat`:
```batch
@echo off
cd C:\path\to\soc-eater-v2
set GEMINI_API_KEY=your_api_key_here
python -m soc_eater_v2.desktop_app
```

---

## Quick Start

1. **Launch the Application**
   ```bash
   soc-eater-desktop
   # or
   python -m soc_eater_v2.desktop_app
   ```

2. **Configure API Key** (first launch)
   - Click **Settings** in the toolbar or menu
   - Enter your Gemini API key
   - Click OK

3. **Analyze an Incident**
   - Select a template or paste your incident details
   - Optionally attach evidence (screenshot or PCAP)
   - Click **Analyze Incident**
   - View results in the right panel

4. **Use Playbooks**
   - Go to the **Playbooks** tab
   - Select a playbook from the list
   - Enter incident data in JSON format
   - Click **Execute Playbook**

---

## User Interface

### Main Window Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│ SOC-EATER v2              [● Connected]           ⚙ Settings       │
├─────────────────────────────────────────────────────────────────────┤
│  🔍 Analyze  │  📋 Playbooks  │  📜 History  │  📊 Statistics       │
├─────────────────────────────────────────────────────────────────────┤
│                                     │                                │
│  ┌─ Incident Input ───────────────┐ │  ┌─ Analysis Results ───────┐ │
│  │ [-- Select Template --]        │ │  │                          │ │
│  │                                │ │  │  EXECUTIVE SUMMARY       │ │
│  │  [Text input area for          │ │  │  ...                     │ │
│  │   incident details...]         │ │  │                          │ │
│  │                                │ │  │  SEVERITY: HIGH          │ │
│  │                                │ │  │  MITRE ATT&CK: T1059     │ │
│  │  [📎] No file selected [✕]    │ │  │                          │ │
│  │                                │ │  │  IOCs:                   │ │
│  │  [🔍 Analyze Incident       ]  │ │  │  - 192.168.1.100        │ │
│  │  [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓]  │ │  │  - malicious.com         │ │
│  └────────────────────────────────┘ │  │                          │ │
│                                     │  │  [📋 Copy] [💾 Export]   │ │
│  ┌─ Quick Actions ─────────────────┐ │  └──────────────────────────┘ │
│  │ [📋 Run Playbook]               │ │                                │
│  └────────────────────────────────┘ │                                │
└─────────────────────────────────────────────────────────────────────┘
```

### Menu Bar

- **File**
  - New Analysis (Ctrl+N)
  - Export Report (Ctrl+E)
  - Exit (Ctrl+Q)

- **Tools**
  - Playbooks (Ctrl+P)
  - Settings (Ctrl+,)

- **Help**
  - About
  - Documentation

---

## Templates

Quick-start templates for common scenarios:

| Template | Description |
|----------|-------------|
| **Phishing Email Alert** | Analyze suspicious emails with indicators |
| **Suspicious PowerShell** | Evaluate PowerShell execution alerts |
| **Malware Detection** | Analyze EDR malware alerts with hashes |
| **Lateral Movement** | Investigate potential lateral movement |
| **Data Exfiltration** | Analyze potential data exfiltration |
| **Custom Incident** | Free-form incident description |

---

## Supported File Types

| File Type | Icon | Use Case |
|-----------|------|----------|
| **Images** (.png, .jpg, .jpeg, .webp) | 📷 | Screenshots of phishing emails, alerts, dashboards |
| **PCAP** (.pcap, .pcapng) | 📦 | Network traffic for IOC extraction |

---

## Analysis Report Features

The desktop app generates comprehensive reports including:

1. **Executive Summary** - 2-3 sentence overview for management
2. **Severity Assessment** - CRITICAL/HIGH/MEDIUM/LOW with confidence
3. **Incident Classification** - Category and MITRE ATT&CK mapping
4. **Investigation Findings** - Detailed attack narrative
5. **IOCs** - IPs, domains, hashes, URLs, emails
6. **Blast Radius** - Affected systems, users, data at risk
7. **Root Cause** - Initial attack vector analysis
8. **Containment Steps** - Immediate actions
9. **Remediation** - Long-term fixes
10. **Detection Queries** - Splunk SPL, Sentinel KQL, Elastic DSL
11. **Threat Intel** - Known actors, campaigns, TTPs
12. **Jira Ticket Draft** - Pre-formatted ticket content

---

## Statistics Dashboard

The Statistics tab tracks:

- **Total Analyses** - Number of incidents analyzed
- **Total Tokens** - Gemini API token usage
- **Total Cost (USD)** - Estimated cost in USD
- **Total Cost (INR)** - Estimated cost in Indian Rupees
- **Avg Response Time** - Average analysis time

---

## Troubleshooting

### "API Key Required" warning

1. Click the ⚙️ Settings button
2. Enter your Gemini API key
3. Click OK

### Application won't start

```bash
# Check Python version
python --version  # Must be 3.11+

# Reinstall dependencies
pip install -r requirements.txt

# Check for errors
python -m soc_eater_v2.desktop_app
```

### Analysis fails with timeout

- Check your internet connection
- Verify API key is valid
- Try again with smaller input

### Dark theme not applying

- The app uses Qt's native dark theme on supported systems
- Some Linux distributions may require Qt6 GTK3 theme:
  ```bash
  pip install qdarkstyle
  ```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC-EATER Desktop GUI                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Menus     │  │  Toolbar    │  │  Tabbed Interface   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                     PyQt6 Core Layer                         │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐│
│  │  Input Panel   │  │  Results Panel │  │  Worker Thread ││
│  └────────────────┘  └────────────────┘  └────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                    Analysis Worker                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │   │
│  │  │ Text     │  │ File     │  │ Playbook         │   │   │
│  │  │ Analysis │  │ Parser   │  │ Executor         │   │   │
│  │  └──────────┘  └──────────┘  └──────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                      SOC Brain (Core)                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Gemini 1.5 Flash API │ Playbooks │ IOC Extraction  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Comparison: Desktop vs Web

| Feature | Desktop App | Web App |
|---------|-------------|---------|
| **Installation** | Install once, run offline | Browser required |
| **Offline Mode** | ✅ Yes (after setup) | ❌ No |
| **Native UI** | ✅ True native | ⚠️ Web-based |
| **Memory Usage** | ~100-200MB | ~300-500MB |
| **Startup Time** | ~2-3s | ~5-10s |
| **Features** | All features | All features |
| **Updates** | Manual or auto-update | Auto via browser |

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Windows 10, macOS 11, Ubuntu 20.04 | Windows 11, macOS 13, Ubuntu 22.04 |
| **Python** | 3.11 | 3.12 |
| **RAM** | 4GB | 8GB |
| **Storage** | 500MB | 1GB |
| **Display** | 1280x720 | 1920x1080 |

---

## Support

- **Documentation**: See README.md, QUICKSTART.md, PLAYBOOKS.md
- **Issues**: https://github.com/soc-eater/soc-eater-v2/issues
- **API Docs**: https://ai.google.dev/docs

---

## License

MIT License - See LICENSE file for details.

---

**Built for security teams who want speed, accuracy, and cost-efficiency. One prompt → Full investigation → Done.** 🎯
