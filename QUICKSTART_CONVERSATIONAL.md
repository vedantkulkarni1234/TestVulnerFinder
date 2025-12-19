# Quick Start: AURORA Conversational Interface

Get up and running with natural language security scanning in 5 minutes.

## 1. Get Your API Key

Visit [Google AI Studio](https://aistudio.google.com/app/apikey) and create a free API key.

## 2. Install AURORA

```bash
# Clone the repository
git clone https://github.com/your-org/aurora.git
cd aurora

# Install dependencies
pip install -e .

# Set your API key
export GOOGLE_API_KEY="your-api-key-here"
```

## 3. Start Chatting

```bash
aurora-chat chat
```

## 4. Try These Commands

Once you're in the chat interface, try these examples:

### Basic Scanning
```
scan example.com
```

### Target Specific Vulnerabilities
```
check example.com for log4shell
```

### Enable Advanced Features
```
enable WAF bypass and stealth mode, then scan myapp.example.com
```

### Learn About Vulnerabilities
```
what is spring4shell?
```

### Get Help
```
what can you do?
```

### Scan Networks
```
scan 192.168.1.0/24 on ports 80, 443, and 8080
```

## 5. One-Shot Commands (Non-Interactive)

Perfect for scripts and automation:

```bash
# Single scan
aurora-chat query "scan example.com for all vulnerabilities"

# With specific modules
aurora-chat query "check test.com for log4shell with OAST enabled"

# Dry run to see what would be executed
aurora-chat query "scan example.com" --dry-run
```

## Common Patterns

### Daily Security Check
```
scan my-production-app.com for all critical vulnerabilities
```

### Incident Response
```
urgent - scan staging.example.com for log4shell before we deploy to production
```

### Network Assessment
```
scan the 10.0.0.0/24 network with stealth mode to avoid IDS alerts
```

### Learning Mode
```
explain log4shell and show me how to test for it
```

## Tips

1. **Be Specific**: "scan example.com for log4shell" works better than "check stuff"
2. **Use Context**: The AI remembers your conversation, so you can say "scan that again with stealth mode"
3. **Ask Questions**: "what is X?" or "explain Y" for learning
4. **Combine Features**: "enable WAF bypass and OAST, then scan example.com"

## Troubleshooting

### "API key required"
```bash
export GOOGLE_API_KEY="your-key-here"
```

### Slow responses?
- This is normal for the first request (AI startup)
- Subsequent requests are faster
- For speed-critical tasks, use the traditional CLI: `aurora scan`

### "Failed to initialize Gemini"
- Check your API key is valid
- Ensure you have internet connectivity
- Verify Google AI services aren't blocked

## What's Next?

- Read the [full guide](CONVERSATIONAL_GUIDE.md) for advanced usage
- Check out [examples](examples/conversational_demo.py) for programmatic API usage
- Try the traditional CLI for maximum performance: `aurora scan --help`

## Security Reminder

⚠️ **Only scan targets you own or have explicit authorization to test.**

The conversational interface makes scanning easy—use this power responsibly!

---

**Need help?** Open an issue on GitHub or check the documentation.

Happy scanning! 🔮✨
