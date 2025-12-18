# NEXUS - Zero-False-Positive Vulnerability Reconnaissance Framework

NEXUS is a professional-grade Bash reconnaissance framework designed for passive detection of historic critical RCE vulnerabilities with mathematically guaranteed zero false positives through mandatory multi-signal correlation.

## 🎯 Features

- **Zero False Positives**: 3-layer signal correlation with mandatory precondition validation
- **9 Critical Vulnerabilities**: Spring4Shell, Log4Shell, Text4Shell, Fastjson, Jackson, Struts2, Kibana, Ghostscript, vm2
- **Professional UI**: Cyberpunk-style terminal interface with progress bars and visual indicators
- **Stealth Mode**: 1 request/10 seconds with realistic headers and random delays
- **Callback Testing**: Optional DNS callback verification for Log4Shell/Text4Shell
- **Multiple Output Formats**: Table, JSON, CSV support
- **Confidence Scoring**: 90%+ CONFIRMED, 70-89% HIGHLY LIKELY, 50-69% POSSIBLE

## 🚀 Quick Start

### Installation

```bash
# One-liner installation
curl -fsSL https://raw.githubusercontent.com/your-org/nexus/main/install.sh | bash

# Or clone and install manually
git clone https://github.com/your-org/nexus.git
cd nexus
chmod +x install.sh
./install.sh
```

### Usage

```bash
# Basic scan
nexus https://target.com

# Stealth mode scan
nexus --stealth https://target.com

# Single vulnerability module
nexus --module log4shell --callback security.nexus.lol https://target.com

# Scan target list
nexus --list targets.txt

# JSON output
nexus --output json --all 192.168.1.0/24:80,443,8080
```

## 📋 Supported Vulnerabilities

| Vulnerability | CVE | Severity | Detection Method |
|---------------|-----|----------|------------------|
| Spring4Shell | CVE-2022-22965 | CRITICAL | Multi-signal correlation |
| Log4Shell | CVE-2021-44228 | CRITICAL | DNS callback + version |
| Text4Shell | CVE-2022-42889 | CRITICAL | DNS callback + version |
| Fastjson RCE | CVE-2017-18349 | CRITICAL | Autotype + deserialization |
| Jackson RCE | CVE-2019-12384 | CRITICAL | Polymorphic + version |
| Struts2 RCE | CVE-2017-5638 | CRITICAL | OGNL + Content-Type |
| Kibana RCE | CVE-2019-7609 | HIGH | Prototype pollution |
| Ghostscript RCE | CVE-2018-16509 | HIGH | ImageMagick + PostScript |
| vm2 Sandbox Escape | CVE-2023-37466 | HIGH | JavaScript + sandbox |

## 🔧 Technical Architecture

### Detection Methodology

NEXUS implements a **3-layer signal correlation** approach:

1. **Technology Fingerprinting**: Identify frameworks, libraries, and versions
2. **Version Confirmation**: Verify vulnerable version ranges
3. **Behavioral Validation**: Test precondition matrices and exploit surfaces

### Confidence Scoring

- **CONFIRMED (≥90%)**: All mandatory preconditions met
- **HIGHLY LIKELY (70-89%)**: Strong correlation with minor gaps
- **POSSIBLE (50-69%)**: Moderate correlation, requires validation
- **BELOW 50%**: Silently discarded to maintain zero false positives

### Precondition Matrices

Each vulnerability has strict preconditions:

#### Spring4Shell (CVE-2022-22965)
- ✓ Spring Framework detected
- ✓ JDK ≥ 9 confirmed
- ✓ WAR deployment confirmed
- ✓ Apache Tomcat detected
- ✓ ClassLoader manipulation surface present

#### Log4Shell (CVE-2021-44228)
- ✓ Log4j library fingerprint
- ✓ Vulnerable version range
- ✓ JNDI lookup patterns
- ✓ DNS callback confirmation (optional)

## 🎨 Visual Design System

NEXUS features a professional cyberpunk terminal interface:

- **Color Palette**: Cyan, Magenta, Red, Yellow, Green on black
- **Box Drawing**: Heavy borders for headers, light for findings
- **Progress Bars**: ██████░░░░ style with percentages and ETA
- **Severity Indicators**: Color-coded severity badges
- **Confidence Meters**: Visual confidence scoring

## 📖 Command Reference

### Basic Usage
```bash
nexus <TARGET>
```

### Options
- `-h, --help`: Show help message
- `--version`: Show version information
- `-l, --list FILE`: Load targets from file
- `--module NAME`: Run specific vulnerability module
- `--all`: Run all modules (default)
- `--stealth`: Enable stealth mode
- `--callback DOMAIN`: Enable DNS callback for Log4Shell/Text4Shell
- `--output FORMAT`: Output format (table|json|csv)
- `-v, --verbose`: Enable verbose debugging

### Target Formats
- **Single URL**: `nexus https://target.com`
- **Target List**: `nexus -l targets.txt`
- **CIDR Range**: `nexus 192.168.1.0/24:80,443,8080`
- **Domain:Port**: `nexus target.com:8080,8443`

## 🔍 Example Output

### Clean Target (No Findings)
```
╔══════════════════════════════════════════════════════════════╗
║                    SCAN COMPLETE                             ║
╚══════════════════════════════════════════════════════════════╝

NO CRITICAL VULNERABILITIES DETECTED

Target(s) did not meet the strict confidence thresholds for
zero-false-positive vulnerability reporting.

This indicates either:
• No vulnerabilities present
• Vulnerabilities below detection threshold
• Target employing security controls
```

### Confirmed Spring4Shell Finding
```
┌────────────────────────────────────────────────────────────────┐
│ CRITICAL  │ [95%] Spring4Shell (CVE-2022-22965)              │
├────────────────────────────────────────────────────────────────┤
│ Evidence: Spring Framework detected; JDK 9+ confirmed; WAR   │
│ deployment confirmed; Apache Tomcat detected; Spring Boot    │
│ actuator endpoints accessible                                │
└────────────────────────────────────────────────────────────────┘

Confidence Level: CONFIRMED (95%)
Signals Detected: 5
Signal Breakdown:
  ✓ spring4shell_fingerprint (weight: 25)
  ✓ spring4shell_jdk_version (weight: 20)
  ✓ spring4shell_deployment_war (weight: 15)
  ✓ spring4shell_tomcat (weight: 10)
  ✓ spring4shell_actuator_env (weight: 20)
```

## 🛡️ Stealth Mode

Stealth mode implements realistic defensive evasion:

- **Rate Limiting**: 1 request per 10 seconds
- **Random Delays**: 5-15 second randomization
- **Realistic Headers**: Modern browser user agents
- **Request Distribution**: Mimic human browsing patterns

```bash
# Enable stealth mode
nexus --stealth https://sensitive-target.com

# Stealth with DNS callback
nexus --stealth --callback security.nexus.lol https://target.com
```

## 🔄 Callback Testing

For Log4Shell and Text4Shell, DNS callback provides definitive verification:

```bash
# Enable DNS callback testing
nexus --callback security.nexus.lol https://target.com

# The framework will:
# 1. Generate unique callback subdomains
# 2. Test injection points with JNDI payloads
# 3. Monitor DNS lookups for 15 seconds
# 4. Provide zero-day verification if detected
```

## 📊 Output Formats

### Table Format (Default)
Professional terminal interface with visual indicators and severity badges.

### JSON Format
Structured data for integration with other tools:
```json
{
  "target": "https://target.com",
  "vulnerability": "Log4Shell",
  "cve": "CVE-2021-44228",
  "severity": "CRITICAL",
  "confidence": 95,
  "level": "CONFIRMED",
  "evidence": "Log4j library detected; Vulnerable Log4j version; JNDI lookup patterns detected; DNS callback confirmed",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### CSV Format
Compatible with spreadsheet applications and SIEM tools.

## 🔧 Dependencies

Core dependencies (automatically installed):
- `curl`: HTTP requests
- `jq`: JSON processing
- `nmap`: Network enumeration
- `openssl`: SSL/TLS operations
- `dig`: DNS lookups
- `awk`, `sed`, `grep`: Text processing

## ⚠️ Legal Notice

NEXUS is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors assume no liability for misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct before submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🏗️ Development

```bash
# Clone repository
git clone https://github.com/your-org/nexus.git
cd nexus

# Run tests
./test.sh

# Build documentation
./docs.sh

# Install development dependencies
./dev-setup.sh
```

---

**NEXUS** - *Professional Offensive Security Reconnaissance*