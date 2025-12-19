
---

# AURORA: High-Confidence RCE Reconnaissance

```text
 █████╗ ██╗   ██╗██████╗  ██████╗ ██████╗  █████╗ 
██╔══██╗██║   ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗
███████║██║   ██║██████╔╝██║   ██║██████╔╝███████║
██╔══██║██║   ██║██╔══██╗██║   ██║██╔══██╗██╔══██║
██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

```

**AURORA** is a strictly non-exploitative, evidence-driven reconnaissance framework designed to detect historic Java and Node.js RCE chains with high confidence. Unlike traditional scanners, AURORA focuses on specific, high-impact vulnerabilities using safe proofs of concept, deep protocol analysis, and active verification.

---

## 🔮 Key Features

### 🧠 **Aurora Conversational Assistant**

Interact with your security tool using natural language, powered by **Google Gemini 2.5 Flash**.

* **Natural Language Scanning:** "Scan example.com for Log4Shell with stealth mode enabled."
* **Context Awareness:** Remembers previous targets and settings across turns.
* **Vulnerability Explanation:** Ask "Explain Spring4Shell" to get detailed technical breakdowns.

### 👻 **"Ghost Update" Engine**

Advanced evasion and distributed capabilities for modern environments:

* **🛡️ Specter WAF Bypass:** Evade firewalls using header mutation, capitalization strategies, and HTTP request smuggling (CL.TE/TE.CL).
* **🕸️ Hive Mind:** Distributed scanning architecture allowing a Master node to coordinate 50+ Workers via Redis or ZeroMQ.
* **📡 Sonar OAST:** Integrated **interact.sh** listener for real-time out-of-band callback detection (DNS/LDAP/HTTP).

---

## 🎯 Supported Modules

AURORA focuses on critical Remote Code Execution (RCE) chains.

| Module | Vulnerability | CVE | Tech Stack |
| --- | --- | --- | --- |
| **Log4Shell** | JNDI Injection | `CVE-2021-44228` | Java (Log4j) |
| **Spring4Shell** | Class Loader Manipulation | `CVE-2022-22965` | Java (Spring) |
| **Text4Shell** | String Interpolation | `CVE-2022-42889` | Java (Commons Text) |
| **Struts2** | Multipart Parser RCE | `CVE-2017-5638` | Java (Struts) |
| **Fastjson** | Deserialization | `CVE-2017-18349` | Java |
| **Jackson** | Polymorphic Deserialization | `CVE-2019-12384` | Java |
| **VM2** | Sandbox Escape | `CVE-2023-37466` | Node.js |
| **Kibana** | Prototype Pollution | `CVE-2019-7609` | Node.js (ELK) |
| **Ghostscript** | Image Pipeline RCE | `CVE-2018-16509` | System Tools |

---

## 🚀 Installation

Requires **Python 3.11+**.

```bash
# Clone the repository
git clone https://github.com/vedantkulkarni1234/TestVulnerFinder.git
cd aurora

# Install dependencies
pip install -e .

# Optional: Install specialized dependencies
pip install -e ".[all]"  # Includes Redis, ZeroMQ, and Interactsh support

```

---

## 💻 Usage

### 1. Conversational Mode (Recommended)

Launch the AI-powered assistant. Requires `GOOGLE_API_KEY`.

```bash
export GOOGLE_API_KEY="your-api-key"
aurora-chat chat

```

**Example Conversation:**

> **You:** Scan 10.0.0.0/24 for Spring4Shell.
> **Aurora:** 🎯 Scanning 256 target(s) with 1 module(s)...
> **You:** Now enable WAF bypass and check example.com.
> **Aurora:** Preferences updated! Scanning example.com with Specter mode enabled...

### 2. CLI Mode

Standard command-line interface for automation.

```bash
# Basic Scan
aurora scan https://target.com --modules log4shell,spring4shell

# Advanced Scan (Stealth + WAF Bypass + OAST)
aurora scan targets.txt \
  --stealth \
  --enable-waf-bypass \
  --oast-domain "interact.sh" \
  --concurrency 50

```

### 3. CLI Options Reference

| Option | Description |
| --- | --- |
| `--stealth` | Enables randomized delays and jitter to avoid rate limits. |
| `--enable-waf-bypass` | Activates "Specter" mode (Header mutation, IP spoofing, Smuggling). |
| `--enable-sonar` | Starts the local OAST listener for callback verification. |
| `--enable-distributed` | Activates "Hive Mind" mode using Redis. |
| `--cidr <range>` | Expands and scans a CIDR range (e.g., `192.168.1.0/24`). |

---

## 📊 Reporting

AURORA supports multiple output formats.

```bash
# Export results to HTML report
aurora scan example.com --output html --output-file report.html

```

* **Rich:** Beautiful console output (default).
* **JSON:** Full data for integration.
* **Markdown:** Github-ready summary.
* **HTML:** Standalone reporting file.

---

## ⚖️ Disclaimer

**AURORA is for authorized security testing only.**
The code provided in this repository is intended for security professionals to assess the posture of systems they own or have explicit permission to test. The authors are not responsible for misuse or illegal acts.

* **Recon-Only:** Payloads are designed to be non-destructive triggers (e.g., `DNS` lookups or `sleep` calls) and do not attempt to execute arbitrary system commands unless configured explicitly for Proof-of-Concept verification.

---

**License:** [MIT License](https://www.google.com/search?q=LICENSE)
