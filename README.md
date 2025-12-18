# AURORA

AURORA is a Python 3.11+ asynchronous reconnaissance tool focused on **high-confidence, evidence-attributed detection** of environments exposed to nine legendary Java/Node RCE chains.

It is intentionally **recon-only**:
- no exploitation payloads (except opt-in OAST trigger strings for Log4Shell/Text4Shell)
- no authentication bypass attempts
- every finding is accompanied by structured evidence provenance

---

## 1) Cyberpunk ASCII banner (3 variants)

### Small

```text
AURORA :: high-confidence RCE reconnaissance
────────────────────────────────────────
```

### Medium

```text
    ___  __  ______  ____  ___    
   / _ |/ / / / __ \/ __ \/ _ \   
  / __ / /_/ / /_/ / /_/ / , _/   
 /_/ |_|\____/\____/\____/_/|_|    
  A U R O R A  ::  Reconnaissance  
───────────────────────────────────
```

### Large

```text
 █████╗ ██╗   ██╗██████╗  ██████╗ ██████╗  █████╗ 
██╔══██╗██║   ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗
███████║██║   ██║██████╔╝██║   ██║██████╔╝███████║
██╔══██║██║   ██║██╔══██╗██║   ██║██╔══██╗██╔══██║
██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
      High-Confidence Recon for Legendary RCE Chains
────────────────────────────────────────────────────
```

---

## 2) Project structure

```text
.
├── aurora.py               # Typer CLI entrypoint
├── core/
│   ├── __init__.py
│   ├── engine.py           # async scanner w/ concurrency + global rate limit
│   ├── http.py             # httpx wrapper + evidence capture
│   ├── fingerprint.py      # universal tech fingerprinting
│   ├── scoring.py          # confidence tiers + bar rendering
│   └── evidence.py         # structured evidence + provenance
├── modules/
│   ├── __init__.py
│   ├── spring4shell.py     # strict 5-precondition matrix
│   ├── log4shell.py        # optional OAST trigger mode
│   ├── text4shell.py       # optional OAST trigger mode
│   ├── fastjson.py
│   ├── jackson.py
│   ├── struts2.py
│   ├── kibana.py
│   ├── ghostscript.py
│   └── vm2.py
├── ui/
│   ├── __init__.py
│   ├── theme.py            # Rich theme + palette
│   ├── renderer.py         # panels, progress, summary + exports
│   └── banner.py
├── utils/
│   ├── __init__.py
│   ├── helpers.py          # targets, CIDR expansion, version parsing
│   └── oast.py             # OAST token + trigger string builders
├── pyproject.toml
├── README.md
└── .gitignore
```

---

## 3) Visual design system (Rich)

**Palette** (see `ui/theme.py`):
- cyan: `#00f5ff`
- magenta: `#ff00ff`
- green: `#39ff14`
- red: `#ff1744`
- yellow: `#ffe600`
- muted: `#6b7280`

**Panels**
- heavy borders (`box.HEAVY`)
- neon magenta borders for findings
- cyan borders for final summary

**Confidence bars**

Rendered as: `████████░░░░ 73%` (see `core/scoring.py`).

**Tiering (strict display filter)**
- `CONFIRMED`      ≥ 92%
- `HIGHLY_LIKELY`  78–91%
- `POSSIBLE`       55–77%
- below 55%: discarded unless `--verbose`

---

## 4) Implementation notes (detection philosophy)

AURORA enforces **evidence provenance**:
- Every HTTP probe is recorded into the per-target `EvidenceStore`
- Findings include `evidence_ids` that can be resolved back to raw observations

AURORA is **conservative by design**:
- Modules avoid reporting unless they can anchor on high-signal indicators (versions, runtime stack identifiers)
- Spring4Shell requires **all 5** preconditions to be independently confirmed before a `CONFIRMED` finding is emitted

---

## 5) Live terminal output mockups

### Startup + scanning dashboard

```text
█████╗ ...
┏━━━━━━━━━━━━━━━◉ scan configuration━━━━━━━━━━━━━━━┓
┃ targets      250                                ┃
┃ modules      spring4shell,log4shell,text4shell   ┃
┃ stealth      on                                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
AURORA • scanning ███████████░░░░░░░░░░░░  42/250 • 00:12 • 133.7 req/s
```

### Real-time findings

```text
┏━━━━━━━━━━━━━━━━━━CONFIRMED  Spring4Shell  ████████████  95%━━━━━━━━━━━━━━━━━━┓
┃ target  https://target.example.com                                           ┃
┃ module  spring4shell                                                         ┃
┃ cve     CVE-2022-22965                                                       ┃
┃ summary All Spring4Shell preconditions independently confirmed...             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

### Final summary table

```text
┏━━━━━━━━━━━━━━━◆ summary━━━━━━━━━━━━━━━┓
┃ tier           count                  ┃
┃ CONFIRMED      1                      ┃
┃ HIGHLY LIKELY  2                      ┃
┃ POSSIBLE       5                      ┃
┃ TOTAL          8                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

### JSON report sample (excerpt)

```json
{
  "generated_at": "2025-12-18T00:00:00+00:00",
  "results": [
    {
      "target": "https://target.example.com",
      "fingerprint": {
        "server": "Apache Tomcat/9.0.54",
        "powered_by": null,
        "frameworks": ["spring"],
        "containers": ["tomcat"],
        "languages": ["java"],
        "products": []
      },
      "findings": [
        {
          "module": "spring4shell",
          "vulnerability": "Spring4Shell",
          "cve": "CVE-2022-22965",
          "title": "Spring Framework RCE chain preconditions satisfied",
          "confidence": 95,
          "tier": "CONFIRMED",
          "summary": "All Spring4Shell preconditions independently confirmed...",
          "evidence_ids": ["d8c2f4b80a3eaa02", "..."]
        }
      ],
      "evidence": {"items": ["..."]}
    }
  ]
}
```

### Export to Markdown/HTML

```bash
aurora scan -l targets.txt --output markdown
aurora scan -l targets.txt --output html
```

---

## 6) Installation & usage

### Install (uv)

```bash
uv venv
source .venv/bin/activate
uv pip install -e .

aurora scan https://target.example.com
```

### Install (pip)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

aurora scan -l targets.txt --concurrency 50 --rate-limit 15
```

### Usage examples

```bash
aurora scan https://target.example.com

aurora scan -l targets.txt --concurrency 50 --rate-limit 15

aurora scan https://target.example.com --modules spring4shell,log4shell --output json

aurora scan https://target.example.com --stealth --user-agent "Mozilla/5.0..."

# Explicit opt-in: send OAST trigger strings for Log4Shell/Text4Shell
aurora scan https://target.example.com --modules log4shell,text4shell --oast-domain oast.example.org
```
