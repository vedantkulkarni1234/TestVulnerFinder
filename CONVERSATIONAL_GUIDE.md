# AURORA Conversational Assistant Guide

## Overview

AURORA now features a revolutionary conversational interface powered by **Gemini 2.5 Flash**, transforming the tool from a traditional CLI application into an intelligent, natural language-driven security scanning companion.

Instead of memorizing complex command-line flags and syntax, you can now interact with AURORA through plain English (or any language Gemini supports), making security reconnaissance accessible to everyone from seasoned penetration testers to developers learning about vulnerabilities.

## Why Conversational?

Traditional security tools require you to:
- 📚 Remember dozens of command-line flags
- 🤔 Understand technical jargon and abbreviations
- 📖 Constantly reference documentation
- 🔄 Repeat complex commands for similar tasks

The conversational interface eliminates these friction points:
- 💬 Just describe what you want in natural language
- 🧠 The AI understands intent and context
- 🔄 Maintains conversation history for follow-ups
- 🎯 Suggests optimizations based on your needs

## Getting Started

### Prerequisites

1. **Google AI API Key**: Get your free API key from [Google AI Studio](https://aistudio.google.com/app/apikey)

2. **Install AURORA with dependencies**:
   ```bash
   pip install -e .
   # Or with all features:
   pip install -e ".[all]"
   ```

3. **Set your API key**:
   ```bash
   export GOOGLE_API_KEY="your-api-key-here"
   ```

### Quick Start

#### Interactive Mode (Recommended)

Start a persistent chat session:

```bash
aurora-chat chat
```

This opens an interactive prompt where you can have multi-turn conversations:

```
You: scan example.com for log4shell
Aurora: I'll scan example.com for Log4Shell vulnerabilities...
[scan executes]

You: also check it for spring4shell
Aurora: I'll scan the same target for Spring4Shell now...
[scan executes using context]

You: what is log4shell?
Aurora: Log4Shell (CVE-2021-44228) is a critical remote code execution...
```

#### One-Shot Mode (For Scripting)

Execute a single command without entering interactive mode:

```bash
aurora-chat query "scan example.com for all vulnerabilities"
```

Perfect for automation, CI/CD pipelines, or quick one-off scans.

## Natural Language Examples

### Basic Scanning

**Instead of:**
```bash
aurora scan https://example.com --modules log4shell,spring4shell
```

**Just say:**
```
scan example.com for log4shell and spring4shell
```

### Advanced Features

**WAF Bypass (Specter Mode):**
```
enable WAF bypass and scan myapp.example.com
```

**Stealth Scanning:**
```
use stealth mode to scan sensitive-target.com quietly
```

**OAST/Callback Detection (Sonar Mode):**
```
scan example.com for log4shell with OAST enabled
```

**CIDR Range Scanning:**
```
scan the 192.168.1.0/24 network on ports 80, 443, and 8080
```

**Combined Features:**
```
enable stealth mode and WAF bypass, then scan 10.0.0.0/24 for all vulnerabilities
```

### Information & Learning

**Understand Vulnerabilities:**
```
what is spring4shell?
explain log4shell to me
tell me about CVE-2021-44228
```

**Discover Capabilities:**
```
what can you detect?
list all available modules
show me your features
help
```

**Configuration:**
```
always use stealth mode by default
set default concurrency to 500
enable WAF bypass for all future scans
```

## Conversational Features

### Context Awareness

The assistant remembers your conversation:

```
You: scan example.com
Aurora: [scans]

You: now check test.com too
Aurora: [understands to scan test.com with similar settings]

You: use the same settings on staging.example.com
Aurora: [applies previous configuration]
```

### Intelligent Suggestions

The assistant proactively helps:

```
You: scan for log4shell
Aurora: I notice you're scanning for Log4Shell. Would you like me to 
enable OAST mode for better blind vulnerability detection?
```

### Clarification & Validation

The assistant asks for clarification when needed:

```
You: scan the network
Aurora: Which network would you like to scan? Please provide a target 
URL, IP address, or CIDR range.
```

### Multi-Language Support

Thanks to Gemini's multilingual capabilities, you can use your preferred language:

```
🇪🇸 "escanea ejemplo.com en busca de log4shell"
🇫🇷 "analyser exemple.com pour des vulnérabilités"
🇩🇪 "scanne beispiel.com nach log4shell schwachstellen"
🇯🇵 "example.com を log4shell の脆弱性でスキャンして"
```

## How It Works

### Architecture

```
┌─────────────────┐
│   User Input    │  "scan example.com for log4shell"
│  (Natural Lang) │
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│  Gemini 2.5 Flash   │  Parses intent, understands context
│   Intent Parser     │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Intent Router     │  Maps to Aurora functions
│                     │
├─────────────────────┤
│ - scan_targets()    │  Execute security scan
│ - explain_vuln()    │  Educational content
│ - list_capabilities │  Help & discovery
│ - configure_prefs() │  Set defaults
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Aurora Engine      │  Performs actual scanning
│  (Existing System)  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ Conversational      │  Natural language response
│    Response         │  with scan results
└─────────────────────┘
```

### Function Calling

Under the hood, AURORA uses Gemini's **function calling** capability. The AI doesn't execute arbitrary code—it selects from a defined set of functions:

1. **`scan_targets`**: Execute security scans
2. **`get_scan_status`**: Check scan progress
3. **`explain_vulnerability`**: Educational content
4. **`list_capabilities`**: Feature discovery
5. **`configure_scan_preferences`**: Set defaults

This ensures safety and predictability while maintaining conversational flexibility.

### Context Management

The `ConversationContext` class maintains:
- **History**: Last 10 messages for context
- **Last Targets**: Recent scan targets for reference
- **Preferences**: User-configured defaults
- **State**: Ongoing scan information

This enables intelligent follow-up questions and contextual understanding.

## Advanced Usage

### Custom API Configuration

Use a different API key for specific sessions:

```bash
aurora-chat chat --api-key "alternative-key"
```

### Dry-Run Mode

See what would be executed without actually scanning:

```bash
aurora-chat query "scan example.com" --dry-run
```

Output shows parsed intent:
```
Action: scan
Targets: example.com
Modules: All
Options: {enable_waf_bypass: false, concurrency: 200, ...}
```

### Scripting with Query Mode

Integrate into shell scripts:

```bash
#!/bin/bash
export GOOGLE_API_KEY="your-key"

# Scan multiple targets
for target in $(cat targets.txt); do
    aurora-chat query "scan $target for all vulnerabilities" --output json
done
```

### CI/CD Integration

Add to your security pipeline:

```yaml
# .github/workflows/security-scan.yml
- name: Security Scan
  run: |
    export GOOGLE_API_KEY="${{ secrets.GOOGLE_API_KEY }}"
    aurora-chat query "scan ${{ env.APP_URL }} for all vulnerabilities" --output json > scan-results.json
```

## Comparison: Traditional vs Conversational

### Traditional CLI

```bash
# Complex syntax to remember
aurora scan https://example.com \
  --modules log4shell,spring4shell,text4shell \
  --enable-waf-bypass \
  --enable-stealth \
  --enable-sonar \
  --concurrency 500 \
  --output json \
  --output-file results.json
```

### Conversational Interface

```bash
aurora-chat chat
> enable WAF bypass, stealth, and OAST, then scan example.com 
  for log4shell, spring4shell, and text4shell with high concurrency
```

Or even simpler:
```
> scan example.com thoroughly with all evasion features
```

The AI understands "thoroughly" and "all evasion features" contextually.

## Best Practices

### 1. Be Specific About Targets

✅ **Good**: "scan https://example.com:8443 for log4shell"  
❌ **Vague**: "scan something"

### 2. Mention Features Explicitly When Needed

✅ **Good**: "enable WAF bypass and scan target.com"  
❌ **Assumed**: "bypass the WAF at target.com" (might not enable feature)

### 3. Use Context for Follow-Ups

✅ **Efficient**: 
```
You: scan example.com
You: now check test.com with the same settings
```

### 4. Ask for Explanations When Learning

✅ **Good**: "what is log4shell and how do you detect it?"  
✅ **Good**: "explain the difference between log4shell and spring4shell"

### 5. Configure Defaults for Repeated Tasks

If you always need certain features:
```
You: always enable stealth mode and WAF bypass by default
Aurora: [saves preferences]
You: scan example.com
Aurora: [applies your preferred settings automatically]
```

## Security Considerations

### Ethical Scanning

⚠️ **CRITICAL**: Only scan targets you own or have explicit authorization to test.

The conversational interface makes scanning easier, which also means it's easier to accidentally scan unauthorized targets. AURORA Assistant will remind you of this responsibility.

### API Key Security

- Never commit API keys to version control
- Use environment variables: `export GOOGLE_API_KEY="..."`
- For teams: use secret management (AWS Secrets Manager, HashiCorp Vault, etc.)
- Rotate keys periodically

### Data Privacy

Conversation data is sent to Google's Gemini API:
- Your scan commands and targets are processed by Gemini
- Use the traditional CLI (`aurora scan`) for maximum privacy
- Review Google's data handling: https://ai.google.dev/terms

For air-gapped or highly sensitive environments, use the traditional CLI interface.

## Troubleshooting

### "API key required" Error

```bash
export GOOGLE_API_KEY="your-key-here"
aurora-chat chat
```

Or pass directly:
```bash
aurora-chat chat --api-key "your-key"
```

### "Failed to initialize Gemini" Error

Check:
1. API key is valid (test at https://aistudio.google.com)
2. Internet connectivity
3. No corporate proxy blocking ai.google.dev

### Intent Not Recognized

The AI should be robust, but if it misunderstands:

✅ **Be more explicit**: "scan target example.com for log4shell vulnerability"  
✅ **Use module names**: "use the log4shell module on example.com"  
✅ **Break down complex requests**: Do scanning and configuration separately

### Slow Response

Gemini API latency varies:
- Typical: 1-3 seconds for intent parsing
- Complex requests: 3-5 seconds
- The actual scan time is separate (depends on target count and modules)

For speed-critical automation, use the traditional CLI.

## Migration Guide

### From Traditional CLI to Conversational

You don't need to choose! Both interfaces coexist:

**Use Traditional CLI when:**
- Maximum performance needed
- Scripting with predictable syntax
- Air-gapped environments
- No internet access

**Use Conversational when:**
- Learning AURORA's capabilities
- Ad-hoc exploratory scanning
- Complex multi-feature configurations
- Interactive workflows

### Mapping Commands

| Traditional CLI | Conversational |
|----------------|----------------|
| `aurora scan example.com` | "scan example.com" |
| `aurora scan example.com --modules log4shell` | "scan example.com for log4shell" |
| `aurora scan example.com --enable-waf-bypass` | "enable WAF bypass and scan example.com" |
| `aurora scan example.com --stealth` | "use stealth mode on example.com" |
| `aurora scan example.com --enable-sonar` | "scan example.com with OAST enabled" |

## Future Enhancements

The conversational interface opens exciting possibilities:

- **Multi-modal input**: Upload images of scan targets or network diagrams
- **Voice interface**: "Alexa, scan my staging environment"
- **Automated triage**: "Prioritize findings by exploitability"
- **Natural language reports**: "Summarize findings for management"
- **Learning mode**: "Teach me about RCE vulnerabilities step-by-step"

## Examples Library

### Scenario 1: Daily Security Check

```
You: good morning, run my daily security check on prod-api.example.com

Aurora: Good morning! I'll perform your daily security scan on 
prod-api.example.com. Using your default settings: stealth mode 
enabled, all modules active. Starting now...

[scan executes]

Aurora: Daily scan complete. No new vulnerabilities detected. 
System looks healthy! 🎉
```

### Scenario 2: Incident Response

```
You: urgent - we just deployed to staging.acme.com, need to verify 
it's not vulnerable to log4shell before going to production

Aurora: I understand this is urgent. I'll scan staging.acme.com 
specifically for Log4Shell (CVE-2021-44228). I'll also enable OAST 
mode for thorough detection. Starting immediately...

[scan executes with high priority]

Aurora: ✓ Scan complete in 23 seconds. No Log4Shell vulnerabilities 
detected. Staging environment appears safe for production deployment.
```

### Scenario 3: Learning & Training

```
You: I'm new to security testing. Can you explain what vulnerabilities 
you can detect and show me how to test my local app?

Aurora: Welcome! I'd be happy to help you learn. AURORA specializes in 
detecting critical RCE (Remote Code Execution) vulnerabilities in Java 
and Node.js applications. Let me explain the main ones...

[provides educational content]

Aurora: To test your local app, you could say: "scan localhost:8080 for 
all vulnerabilities". Would you like me to do that now?
```

### Scenario 4: Network-Wide Assessment

```
You: scan my entire internal network 10.0.0.0/16 for critical 
vulnerabilities, but only on web ports and use stealth mode to avoid 
triggering IDS alerts

Aurora: I'll perform a stealth network scan of 10.0.0.0/16 on web 
ports (80, 443, 8080, 8443). This is a large range with ~65,000 
addresses. I recommend:

1. High concurrency for speed (1000 workers)
2. Stealth mode enabled as requested
3. All critical RCE modules active

This will take approximately 30-45 minutes. Shall I proceed?

You: yes

Aurora: Starting network-wide reconnaissance...
```

## Support & Feedback

- **Issues**: https://github.com/your-org/aurora/issues
- **Feature Requests**: Tag with `conversational-interface`
- **Documentation**: https://aurora-docs.example.com

---

**Remember**: With great power comes great responsibility. The conversational interface makes security scanning incredibly accessible—use it ethically and only on authorized targets.

Happy scanning! 🔮✨
