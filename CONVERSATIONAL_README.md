# 🔮 AURORA Conversational Interface

Transform security scanning from a command-line chore into natural conversation.

## Quick Start (60 seconds)

```bash
# 1. Install AURORA
pip install -e .

# 2. Get your free API key from https://aistudio.google.com/app/apikey

# 3. Set your API key
export GOOGLE_API_KEY="your-api-key-here"

# 4. Start chatting
aurora-chat chat
```

## Example Conversation

```
You: scan example.com for log4shell

Aurora: I'll scan example.com for Log4Shell vulnerabilities with 
OAST enabled for better detection...
[scan executes]
✓ Scan complete. No vulnerabilities detected.

You: what is log4shell?

Aurora: Log4Shell (CVE-2021-44228) is a critical remote code 
execution vulnerability in Apache Log4j2...

You: enable WAF bypass and stealth mode, then scan test.com

Aurora: I'll configure WAF evasion and stealth scanning...
[scan executes with advanced features]
```

## Why Conversational?

**Traditional Way:**
```bash
aurora scan https://example.com \
  --modules log4shell,spring4shell \
  --enable-waf-bypass \
  --enable-stealth \
  --enable-sonar \
  --concurrency 500 \
  --output json
```

**Conversational Way:**
```
scan example.com for log4shell and spring4shell with 
all evasion features enabled
```

The AI understands your intent and configures everything automatically.

## Key Features

✨ **Natural Language**: No CLI flags to memorize  
🧠 **Context Aware**: Remembers your conversation  
🎯 **Smart Suggestions**: Recommends features based on your needs  
🌐 **Multilingual**: Works in multiple languages  
📚 **Educational**: Ask questions and learn about vulnerabilities  
⚡ **Both Modes**: Interactive chat or one-shot commands  

## Common Commands

### Scanning
```
scan example.com
check test.com for all vulnerabilities
analyze 192.168.1.0/24 for log4shell
```

### Advanced Features
```
enable WAF bypass and scan myapp.com
use stealth mode to scan sensitive-target.com
scan example.com with OAST enabled
scan 10.0.0.0/24 on ports 80, 443, and 8080
```

### Learning
```
what is spring4shell?
explain log4shell to me
what can you detect?
list all available modules
```

### Configuration
```
always enable stealth mode by default
set default concurrency to 500
```

## One-Shot Mode (For Scripts)

```bash
# Execute single command
aurora-chat query "scan example.com for all vulnerabilities"

# Dry run to see what would happen
aurora-chat query "scan example.com" --dry-run

# In CI/CD pipelines
aurora-chat query "scan $APP_URL for critical vulnerabilities" --output json
```

## Documentation

- **Full Guide**: [CONVERSATIONAL_GUIDE.md](CONVERSATIONAL_GUIDE.md)
- **Quick Start**: [QUICKSTART_CONVERSATIONAL.md](QUICKSTART_CONVERSATIONAL.md)
- **Main README**: [README.md](README.md)

## Security Note

⚠️ **Only scan authorized targets.** The conversational interface makes scanning easy—use this power responsibly.

## Troubleshooting

### No API Key Error
```bash
export GOOGLE_API_KEY="your-key-from-aistudio.google.com"
```

### Want Maximum Privacy?
Use the traditional CLI instead:
```bash
aurora scan example.com --modules all
```

### Slow Response?
- First request: 2-5 seconds (AI initialization)
- Follow-up: 1-2 seconds
- Actual scan time: depends on target

## Support

- **Issues**: GitHub Issues
- **Questions**: GitHub Discussions  
- **Security**: security@example.com

---

**Built with Gemini 2.0 Flash | Powered by AURORA**
