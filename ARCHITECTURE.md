# NEXUS Project File Structure

Complete architecture and file organization of the NEXUS vulnerability reconnaissance framework.

```
/home/engine/project/
├── nexus.sh                      # Main entry point and orchestrator
├── install.sh                    # Professional installation script
├── README.md                     # Comprehensive documentation
├── LICENSE                       # MIT license
├── examples/
│   └── terminal-outputs.md      # Example terminal outputs and visual design
├── lib/                          # Core framework libraries
│   ├── colors.sh                # Color system and formatting
│   ├── ui.sh                    # User interface components
│   ├── http.sh                  # HTTP request engine
│   ├── fingerprint.sh           # Technology fingerprinting
│   ├── confidence.sh            # Confidence scoring engine
│   └── reporting.sh             # Final report generation
└── modules/                      # Vulnerability detection modules
    ├── detect_spring4shell.sh   # CVE-2022-22965
    ├── detect_log4shell.sh      # CVE-2021-44228
    ├── detect_text4shell.sh     # CVE-2022-42889
    ├── detect_fastjson.sh       # CVE-2017-18349 et al.
    ├── detect_jackson.sh        # CVE-2019-12384 et al.
    ├── detect_struts2.sh        # CVE-2017-5638
    ├── detect_kibana.sh         # CVE-2019-7609
    ├── detect_ghostscript.sh    # CVE-2018-16509
    └── detect_vm2.sh            # CVE-2023-37466
```

## Core Architecture Components

### 1. Main Orchestrator (`nexus.sh`)
- **Size**: ~250 lines
- **Responsibilities**: 
  - Command-line argument parsing
  - Framework initialization
  - Target parsing (URL, file, CIDR)
  - Module loading and execution
  - Results orchestration
  - Dependency validation

### 2. Core Libraries (`lib/`)

#### 2.1 Color System (`colors.sh`)
- **256-color safe**: Full palette support
- **Fallback**: 16-color compatibility
- **Box drawing**: Unicode character sets
- **Semantic colors**: Severity and confidence mapping

#### 2.2 User Interface (`ui.sh`)
- **Banner generation**: ASCII art cyberpunk styling
- **Progress indicators**: Animated progress bars with ETA
- **Visual components**: Finding cards, summary tables
- **Stage headers**: Professional section separators

#### 2.3 HTTP Engine (`http.sh`)
- **Stealth mode**: Rate limiting and realistic headers
- **Response parsing**: Full response details extraction
- **DNS callbacks**: Optional callback verification
- **Error handling**: Robust failure management

#### 2.4 Fingerprinting (`fingerprint.sh`)
- **Technology detection**: Framework and library identification
- **Version extraction**: Multiple source correlation
- **Precondition validation**: Deployment type detection
- **Cache system**: Performance optimization

#### 2.5 Confidence Engine (`confidence.sh`)
- **Signal weighting**: Vulnerability-specific weights
- **Correlation analysis**: Multi-layer signal validation
- **Threshold management**: CONFIRMED/HIGHLY_LIKELY/POSSIBLE
- **Precondition matrices**: Strict validation rules

#### 2.6 Reporting System (`reporting.sh`)
- **Final aggregation**: Complete result compilation
- **Statistical analysis**: Severity and confidence distribution
- **Visual formatting**: Professional summary tables
- **Multi-format output**: Table, JSON, CSV support

### 3. Vulnerability Detection Modules (`modules/`)

Each module follows consistent architecture:

#### Standard Module Structure:
```bash
#!/bin/bash
# Module: detect_[vulnerability].sh

# Main detection function
detect_[vulnerability]() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    # Initialize confidence tracking
    # Collect detection signals
    # Apply correlation logic
    # Calculate confidence
    # Render findings
}

# Signal collection functions
collect_[vulnerability]_signals() {
    # Layer 1: Technology fingerprinting
    # Layer 2: Version confirmation
    # Layer 3: Behavioral validation
}

# Specialized testing functions
test_[vulnerability]_specific() {
    # Vulnerability-specific validation
    # Exploitation surface detection
    # Callback verification
}

# Rendering functions
render_[vulnerability]_finding() {
    # Visual finding card
    # Evidence compilation
    # Confidence explanation
}
```

#### Module Specifications:

**1. Spring4Shell (`detect_spring4shell.sh`)**
- **Preconditions**: Spring Framework + JDK ≥9 + WAR + Tomcat + Actuator
- **Signals**: 5 mandatory signals (85% base confidence)
- **Version Range**: Spring Framework 5.3.0-5.3.17, 6.0.0-6.0.2
- **CVE**: CVE-2022-22965

**2. Log4Shell (`detect_log4shell.sh`)**
- **Preconditions**: Log4j library + vulnerable version + JNDI enabled
- **Signals**: 4 signals (85% base confidence)
- **Version Range**: Log4j 2.0.0-2.14.1
- **CVE**: CVE-2021-44228
- **Callback**: DNS lookup verification supported

**3. Text4Shell (`detect_text4shell.sh`)**
- **Preconditions**: Apache Commons Text + vulnerable version + Script eval
- **Signals**: 4 signals (80% base confidence)
- **Version Range**: Commons Text 1.6-1.9
- **CVE**: CVE-2022-42889
- **Callback**: DNS lookup verification supported

**4. Fastjson RCE (`detect_fastjson.sh`)**
- **Preconditions**: Fastjson library + vulnerable version + Autotype enabled
- **Signals**: 5 signals (80% base confidence)
- **Version Range**: Fastjson 1.2.0-1.2.47
- **CVE**: CVE-2017-18349 et al.

**5. Jackson RCE (`detect_jackson.sh`)**
- **Preconditions**: Jackson library + vulnerable version + Polymorphic types
- **Signals**: 5 signals (80% base confidence)
- **Version Range**: Jackson 2.9.0-2.10.5
- **CVE**: CVE-2019-12384 et al.

**6. Struts2 RCE (`detect_struts2.sh`)**
- **Preconditions**: Struts2 + vulnerable version + OGNL patterns
- **Signals**: 4 signals (90% base confidence)
- **Version Range**: Struts2 2.3.5-2.3.31, 2.5.0-2.5.10
- **CVE**: CVE-2017-5638

**7. Kibana RCE (`detect_kibana.sh`)**
- **Preconditions**: Kibana + vulnerable version + Timelion/Canvas
- **Signals**: 4 signals (75% base confidence)
- **Version Range**: Kibana 6.0.0-6.6.1
- **CVE**: CVE-2019-7609

**8. Ghostscript RCE (`detect_ghostscript.sh`)**
- **Preconditions**: ImageMagick + Ghostscript + vulnerable version
- **Signals**: 4 signals (70% base confidence)
- **Version Range**: Ghostscript 9.22-9.25
- **CVE**: CVE-2018-16509

**9. vm2 Sandbox Escape (`detect_vm2.sh`)**
- **Preconditions**: Node.js + vm2 + vulnerable version + Sandbox surface
- **Signals**: 4 signals (75% base confidence)
- **Version Range**: vm2 3.9.0-3.9.18
- **CVE**: CVE-2023-37466

## Dependency Management

### Core Dependencies (Required)
- `bash` ≥ 4.0: Shell scripting language
- `curl`: HTTP client for requests
- `jq`: JSON processing and manipulation
- `nmap`: Network host enumeration
- `openssl`: SSL/TLS operations and crypto
- `dig`: DNS lookup utilities

### Optional Dependencies
- `bc`: Mathematical calculations (confidence scoring)
- `nc`: Netcat for advanced network testing
- `timeout`: Process timeout management

### Installation Detection
The `install.sh` script automatically detects and installs missing dependencies based on the operating system:

- **Linux**: Uses `apt-get` for package management
- **macOS**: Uses `Homebrew` for package management
- **Manual**: Provides instructions for manual installation

## Configuration System

### Runtime Configuration (`~/.nexus/config.sh`)
```bash
export NEXUS_CONFIG_DIR="$HOME/.nexus"
export NEXUS_CACHE_DIR="$NEXUS_CONFIG_DIR/cache"
export NEXUS_LOG_DIR="$NEXUS_CONFIG_DIR/logs"
export NEXUS_USER_AGENT="Mozilla/5.0 (compatible; NEXUS/1.0)"
export NEXUS_STEALTH_MODE="false"
export NEXUS_CONFIDENCE_THRESHOLD="50"
export NEXUS_TIMEOUT="10"
export NEXUS_MAX_RETRIES="2"
```

### Cache System
- **Purpose**: Reduce redundant network requests
- **Storage**: `~/.nexus/cache/`
- **TTL**: 1 hour for fingerprint data
- **Format**: MD5-based filename keys

### Logging System
- **Location**: `~/.nexus/logs/`
- **Rotation**: Automatic daily rotation
- **Levels**: DEBUG, INFO, WARN, ERROR
- **Format**: Structured JSON logging

## Security Considerations

### Input Validation
- URL format validation
- CIDR range parsing
- File path sanitization
- Command injection prevention

### Network Safety
- Stealth mode rate limiting
- Respectful request timing
- Connection timeout management
- Error handling without exploitation

### Data Protection
- No payload storage in results
- Temporary file cleanup
- Secure callback domain handling
- Memory-safe string operations

## Performance Optimization

### Caching Strategy
- Fingerprint result caching
- DNS resolution caching
- HTTP response caching
- Version information caching

### Parallel Processing
- Target-based parallelism
- Module-based concurrency (future enhancement)
- I/O optimization
- Memory efficiency

### Resource Management
- Temporary file cleanup
- Process timeout handling
- Memory usage monitoring
- CPU usage optimization

## Testing and Quality Assurance

### Code Quality
- ShellCheck compliance
- POSIX compatibility where possible
- Error handling robustness
- Documentation coverage

### Testing Framework
- Unit testing for individual modules
- Integration testing for workflows
- Performance benchmarking
- Security validation

### Continuous Integration
- Automated dependency checking
- Code style enforcement
- Security scanning
- Documentation generation

## Deployment and Distribution

### Installation Methods
1. **One-liner curl installation**: `curl -fsSL https://.../install.sh | bash`
2. **Manual installation**: Download and run `install.sh`
3. **Package manager**: Future support for apt, brew, etc.
4. **Container deployment**: Docker image support

### Release Management
- Semantic versioning (MAJOR.MINOR.PATCH)
- Changelog maintenance
- Security update process
- Backward compatibility policy

This comprehensive file structure ensures maintainability, extensibility, and professional-grade reliability for the NEXUS framework.