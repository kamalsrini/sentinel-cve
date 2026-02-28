# Sentinel — CVE Explainer & Repo Impact Scanner

> **"Does this CVE even affect me?"** — answered in seconds, not hours.

Sentinel is a CLI tool (and Telegram bot) powered by Claude that takes a CVE ID, fetches all relevant data, and returns a clear, actionable 5-section breakdown. It can also scan your codebase to tell you whether a specific vulnerability actually impacts your project.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [CLI Interface Design](#3-cli-interface-design)
4. [CVE Explainer Pipeline](#4-cve-explainer-pipeline)
5. [Repo Scanner Pipeline](#5-repo-scanner-pipeline)
6. [Telegram/Messaging Integration](#6-telegrammessaging-integration)
7. [Tech Stack](#7-tech-stack)
8. [Output Templates](#8-output-templates)
9. [Security & Privacy](#9-security--privacy)
10. [Implementation Phases](#10-implementation-phases)

---

## 1. Overview

### The Problem

- **CVE fatigue**: Thousands of CVEs published yearly. Most advisories are dense, jargon-heavy, and hard to act on.
- **"Does this affect me?"**: The hardest question. You read a CVE, then manually check your deps, versions, and code paths. Tedious.
- **Scattered data**: Info lives across NVD, GitHub Advisories, vendor blogs, ExploitDB. No single source gives you the full picture.
- **Slow response**: Security teams spend hours triaging a single CVE when the answer is often "not affected."

### The Solution

```
$ sentinel cve CVE-2026-12345
```

One command. Five sections. Done:

| Section | What it answers |
|---|---|
| **What it is** | Plain-English explanation |
| **How to exploit** | Attack vector, PoC summary |
| **Who should panic** | Affected software, versions, ecosystems |
| **How to patch safely** | Remediation steps, patch links |
| **What to test** | Verification steps after patching |

Plus repo scanning:

```
$ sentinel scan ./my-project --cve CVE-2026-12345
✅ Not Affected — your version of libfoo (2.3.1) is patched.
```

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────┐
│                    User Interface                     │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────┐ │
│  │  CLI (click) │  │ Telegram  │  │  JSON API (future)│ │
│  └──────┬────┘  └─────┬─────┘  └────────┬─────────┘ │
│         │             │                  │           │
│         └─────────────┼──────────────────┘           │
│                       ▼                              │
│              ┌────────────────┐                      │
│              │  Sentinel Core │                      │
│              └───────┬────────┘                      │
│         ┌────────────┼────────────┐                  │
│         ▼            ▼            ▼                  │
│  ┌────────────┐ ┌──────────┐ ┌──────────────┐       │
│  │ CVE Fetcher│ │ Repo     │ │ Claude       │       │
│  │ (NVD, GHSA,│ │ Scanner  │ │ Synthesizer  │       │
│  │  OSV, etc.)│ │          │ │              │       │
│  └────────────┘ └──────────┘ └──────────────┘       │
│         │            │            ▲                  │
│         │            │            │                  │
│         └────────────┴────────────┘                  │
│                                                      │
│  ┌──────────────────────────────────────────┐        │
│  │          Local Cache (SQLite)            │        │
│  └──────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────┘
```

### Components

| Component | Role |
|---|---|
| **CLI** | User-facing `sentinel` command via `click` |
| **CVE Fetcher** | Pulls data from NVD, GitHub Advisory DB, OSV.dev, ExploitDB |
| **Repo Scanner** | Parses dependency files, extracts version trees, identifies affected deps |
| **Claude Synthesizer** | Takes raw CVE data (+ optional repo context) and produces the 5-section output |
| **Local Cache** | SQLite DB caching CVE data and analysis results (TTL-based) |
| **Telegram Bridge** | OpenClaw message handler that routes `sentinel` commands to core |

### Data Sources

| Source | What it provides | API |
|---|---|---|
| **NIST NVD** | CVSS scores, descriptions, CPE matches, references | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| **GitHub Advisory DB** | Package-level advisories, affected version ranges | GraphQL `https://api.github.com/graphql` |
| **OSV.dev** | Cross-ecosystem vulnerability data | `https://api.osv.dev/v1/vulns` |
| **ExploitDB** | PoC exploits, exploit metadata | Scraped / API |
| **MITRE CVE** | Canonical CVE records | `https://cveawg.mitre.org/api/cve` |

---

## 3. CLI Interface Design

### Commands

```
sentinel cve <CVE-ID>                          # Explain a CVE (5-section output)
sentinel cve <CVE-ID> --json                   # JSON output
sentinel cve <CVE-ID> --markdown               # Markdown output (for piping)
sentinel cve <CVE-ID> --brief                  # One-paragraph summary only

sentinel scan <path-or-url>                    # Scan repo for ALL known vulns
sentinel scan <path-or-url> --cve <CVE-ID>     # Check specific CVE against repo
sentinel scan <path-or-url> --json             # JSON output
sentinel scan <path-or-url> --deep             # Enable Claude code-path analysis
sentinel scan <path-or-url> --local            # Dependency-only mode (no code sent to API)

sentinel watch <CVE-ID>                        # Monitor CVE for updates (prints diff)
sentinel watch <CVE-ID> --interval 6h          # Custom check interval
sentinel watch --list                          # List watched CVEs
sentinel watch <CVE-ID> --stop                 # Stop watching

sentinel cache clear                           # Clear local cache
sentinel cache stats                           # Show cache size/entries
sentinel config set api-key <key>              # Set Anthropic API key
sentinel config set nvd-key <key>              # Set NVD API key (optional, higher rate limit)
```

### Global Flags

```
--no-color          Disable colored output
--no-cache          Bypass cache, fetch fresh data
--verbose / -v      Show data source details and timing
--quiet / -q        Minimal output (just verdict for scans)
--output / -o FILE  Write output to file
```

---

## 4. CVE Explainer Pipeline

### Step-by-step flow for `sentinel cve CVE-2026-12345`

```
1. CHECK CACHE
   └─ Hit? Return cached result (if < TTL, default 24h)
   └─ Miss? Continue ↓

2. FETCH CVE DATA (parallel)
   ├─ NVD API → CVSS score, description, CPE, references
   ├─ OSV.dev → affected packages, ecosystems, version ranges
   ├─ GitHub Advisory DB → GHSA ID, severity, patched versions
   └─ MITRE CVE → CNA-provided description, references

3. FETCH EXPLOIT DATA
   ├─ Check references for PoC links (github.com PoC repos)
   ├─ ExploitDB search
   └─ Google for "<CVE-ID> exploit" / "<CVE-ID> proof of concept"

4. BUILD CONTEXT DOCUMENT
   └─ Structured text with all fetched data, organized by source

5. SEND TO CLAUDE
   └─ System prompt: "You are a security analyst. Given the following CVE data,
       produce a 5-section report: What it is, How to exploit, Who should panic,
       How to patch safely, What to test. Be specific. Use plain English.
       Include version numbers, package names, and exact commands where possible."
   └─ User message: the context document from step 4

6. CACHE RESULT
   └─ Store in SQLite with timestamp, TTL, source metadata

7. RENDER OUTPUT
   └─ Terminal: rich panels with colored headers
   └─ JSON: structured 5-section object
   └─ Markdown: clean markdown with headers
```

### Claude Prompt Template

```
You are a senior security analyst writing a vulnerability briefing.

Given the raw CVE data below, produce a report with EXACTLY these 5 sections:

## 🔍 What it is
Plain-English explanation. What component is affected? What kind of vulnerability?
No jargon without explanation. A mid-level developer should understand this.

## 💥 How to exploit
Attack vector (network/local/physical). Prerequisites. Summary of how an attacker
would exploit this. If PoC exists, summarize it. Rate difficulty (trivial/moderate/complex).

## 🚨 Who should panic
Affected software, packages, versions, and ecosystems. Be SPECIFIC with version ranges.
"If you use X version Y.Z.0 through Y.Z.9, you are affected."

## 🛡️ How to patch safely
Step-by-step remediation. Exact package versions to upgrade to. Link to patches.
If no patch exists, list mitigations/workarounds. Note any breaking changes in the patch.

## ✅ What to test
After patching: what to verify. Specific test commands, endpoints to check,
or behaviors to confirm. How to know the fix is working.

---

RAW CVE DATA:
{cve_context}
```

### Caching Strategy

| Item | TTL | Storage |
|---|---|---|
| NVD raw data | 24 hours | `~/.sentinel/cache/nvd/` |
| OSV data | 24 hours | `~/.sentinel/cache/osv/` |
| GitHub Advisory data | 24 hours | `~/.sentinel/cache/ghsa/` |
| Claude analysis | 7 days | `~/.sentinel/cache/analysis/` |
| Repo scan results | Until deps change | `~/.sentinel/cache/scans/` |

Backend: SQLite at `~/.sentinel/cache.db`

---

## 5. Repo Scanner Pipeline

### Step-by-step flow for `sentinel scan /path/to/repo --cve CVE-2026-12345`

```
1. DETECT PROJECT TYPE
   └─ Walk repo root for known dependency files:
      ├─ package.json / package-lock.json / yarn.lock  → Node.js
      ├─ requirements.txt / Pipfile / pyproject.toml   → Python
      ├─ go.mod / go.sum                               → Go
      ├─ Cargo.toml / Cargo.lock                       → Rust
      ├─ pom.xml / build.gradle                        → Java
      ├─ Gemfile / Gemfile.lock                        → Ruby
      ├─ composer.json / composer.lock                  → PHP
      ├─ mix.exs                                       → Elixir
      └─ *.csproj / packages.config                    → .NET

2. EXTRACT DEPENDENCIES
   └─ Parse lockfiles (preferred) or manifest files
   └─ Build flat dependency list: [{name, version, ecosystem}]
   └─ For deep mode: also extract transitive deps

3. IF --cve PROVIDED:
   ├─ Fetch CVE data (same as explainer pipeline)
   ├─ Get affected package names + version ranges from OSV/GHSA
   ├─ Match against extracted dependencies
   ├─ Result: AFFECTED / NOT AFFECTED / UNKNOWN
   │
   └─ IF --deep AND AFFECTED:
      ├─ Identify which dependency is affected
      ├─ Find import/usage of that dependency in source files
      ├─ Send relevant source snippets to Claude
      ├─ Claude determines: "vulnerable code path used?" 
      └─ Result: AFFECTED (confirmed) / POTENTIALLY AFFECTED (uses dep but
         unclear if vulnerable path) / NOT AFFECTED (dep present but
         vulnerable function not called)

4. IF NO --cve (full scan):
   ├─ For each dependency, query OSV.dev batch API
   ├─ Collect all known CVEs affecting current versions
   ├─ For each found CVE, run explainer pipeline
   └─ Output: sorted by severity (Critical → Low)

5. FOR GITHUB URLs:
   ├─ Clone to temp directory (shallow clone, depth=1)
   ├─ Run scan on cloned repo
   └─ Clean up temp directory
```

### Dependency Parser Module

```python
# sentinel/parsers/__init__.py

PARSERS = {
    "package-lock.json": NodeLockParser,
    "yarn.lock": YarnLockParser,
    "package.json": NodeManifestParser,
    "requirements.txt": PipRequirementsParser,
    "Pipfile.lock": PipfileLockParser,
    "pyproject.toml": PyprojectParser,
    "go.sum": GoSumParser,
    "Cargo.lock": CargoLockParser,
    "pom.xml": MavenParser,
    "Gemfile.lock": BundlerLockParser,
    "composer.lock": ComposerLockParser,
}

@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str  # "npm", "pypi", "go", "crates.io", "maven", "rubygems", "packagist"
    direct: bool    # direct vs transitive
    source_file: str
```

### Verdict Logic

```
IF dependency NOT in affected packages:
    → ✅ Not Affected

IF dependency in affected packages AND version in affected range:
    IF --deep:
        → Run Claude code-path analysis
        → 🔴 Affected (confirmed) / 🟡 Potentially Affected / ✅ Not Affected
    ELSE:
        → 🔴 Affected (version match)

IF dependency in affected packages AND version NOT in affected range:
    → ✅ Not Affected (patched version)

IF dependency in affected packages AND version UNKNOWN:
    → 🟡 Unknown (could not determine version)
```

---

## 6. Telegram/Messaging Integration

### How it works with OpenClaw

OpenClaw's message handling + sub-agent system provides the bridge:

1. User sends message in Telegram: `sentinel CVE-2026-12345`
2. OpenClaw main agent recognizes the `sentinel` prefix
3. Spawns a sub-agent (or runs inline) that:
   - Calls `sentinel cve CVE-2026-12345 --markdown` via shell
   - Captures output
   - Returns formatted result to chat

### Supported Commands in Chat

```
sentinel CVE-2026-12345
sentinel scan https://github.com/user/repo CVE-2026-12345
sentinel scan https://github.com/user/repo
```

### OpenClaw Integration (in SOUL.md or agent config)

The main agent handles this with pattern matching:

```
When user message starts with "sentinel":
  - Parse command (cve / scan)
  - Execute sentinel CLI
  - Return result formatted for Telegram (markdown)
```

### Telegram Output Formatting

- Use Telegram markdown (bold, code blocks)
- Truncate to Telegram's 4096 char limit; if longer, split into multiple messages or attach as file
- For scan results with many CVEs, send summary + offer full report as file

### Example Telegram Flow

```
User: sentinel CVE-2026-12345

Bot:  🔍 *What it is*
      A remote code execution vulnerability in libxml2's XML parser...

      💥 *How to exploit*
      An attacker sends a crafted XML document...

      🚨 *Who should panic*
      libxml2 versions 2.9.0 through 2.9.14...

      🛡️ *How to patch safely*
      Upgrade to libxml2 >= 2.9.15: `apt upgrade libxml2`...

      ✅ *What to test*
      Run: `xmllint --version` (should show 2.9.15+)...
```

---

## 7. Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **Language** | Python 3.11+ | Rich ecosystem for security tooling, async support |
| **CLI Framework** | `click` | Clean decorator-based CLI, auto-generated help |
| **Terminal Output** | `rich` | Panels, colors, tables, markdown rendering |
| **HTTP Client** | `httpx` | Async support, modern API |
| **AI Backend** | Anthropic Claude API (`anthropic` SDK) | Best at structured analysis and plain-English output |
| **Caching** | SQLite via `sqlite3` (stdlib) | Zero-dependency, fast, local |
| **Dependency Parsing** | Custom parsers + `packaging` (for version comparisons) | Need ecosystem-specific parsing |
| **Git Operations** | `gitpython` or subprocess `git` | Clone GitHub repos for scanning |
| **Config** | `~/.sentinel/config.toml` via `tomllib`/`tomli` | Standard config format |
| **Packaging** | `pyproject.toml` + `hatch`/`setuptools` | Modern Python packaging, `pip install sentinel-cve` |
| **Testing** | `pytest` + `pytest-asyncio` | Standard |

### Directory Structure

```
sentinel/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── sentinel/
│       ├── __init__.py
│       ├── __main__.py          # Entry point
│       ├── cli.py               # Click commands
│       ├── core/
│       │   ├── __init__.py
│       │   ├── explainer.py     # CVE explainer pipeline
│       │   ├── scanner.py       # Repo scanner pipeline
│       │   └── watcher.py       # Watch/monitor feature
│       ├── fetchers/
│       │   ├── __init__.py
│       │   ├── nvd.py           # NIST NVD API client
│       │   ├── osv.py           # OSV.dev API client
│       │   ├── ghsa.py          # GitHub Advisory DB client
│       │   ├── exploitdb.py     # ExploitDB lookup
│       │   └── mitre.py         # MITRE CVE API client
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── node.py          # package.json, lockfiles
│       │   ├── python.py        # requirements.txt, pyproject.toml
│       │   ├── go.py            # go.mod, go.sum
│       │   ├── rust.py          # Cargo.toml, Cargo.lock
│       │   ├── java.py          # pom.xml, build.gradle
│       │   ├── ruby.py          # Gemfile, Gemfile.lock
│       │   └── php.py           # composer.json, composer.lock
│       ├── ai/
│       │   ├── __init__.py
│       │   ├── synthesizer.py   # Claude API interaction
│       │   └── prompts.py       # Prompt templates
│       ├── cache/
│       │   ├── __init__.py
│       │   └── store.py         # SQLite cache
│       ├── output/
│       │   ├── __init__.py
│       │   ├── terminal.py      # Rich terminal output
│       │   ├── json_out.py      # JSON formatter
│       │   └── markdown_out.py  # Markdown formatter
│       └── config.py            # Configuration management
├── tests/
│   ├── test_explainer.py
│   ├── test_scanner.py
│   ├── test_parsers/
│   ├── test_fetchers/
│   └── fixtures/                # Sample CVE data, lockfiles
└── docs/
    └── ...
```

---

## 8. Output Templates

### Example: `sentinel cve CVE-2026-12345`

```
╭──────────────────────────────────────────────────────────────╮
│  🛡️  SENTINEL — CVE-2026-12345                              │
│  CVSS: 9.8 (Critical) │ Published: 2026-01-15               │
╰──────────────────────────────────────────────────────────────╯

🔍 WHAT IT IS
  A heap-based buffer overflow in libxml2's xmlParseAttValueComplex()
  function allows remote attackers to execute arbitrary code. When
  parsing a specially crafted XML document with deeply nested entity
  references, the parser writes past the allocated buffer boundary.
  This is a memory corruption bug — the attacker controls what gets
  written and where.

💥 HOW TO EXPLOIT
  Attack Vector: Network (no authentication required)
  Complexity: Low
  Difficulty: ██░░░░░░░░ Trivial

  Any application that parses untrusted XML using libxml2 is vulnerable.
  The attacker sends a crafted XML file with recursive entity expansion.
  Public PoC available: github.com/researcher/CVE-2026-12345-poc

  Exploitation is trivial — the PoC reliably achieves code execution
  on default configurations of affected versions.

🚨 WHO SHOULD PANIC
  ┌─────────────┬─────────────────────┬──────────────┐
  │ Package     │ Affected Versions   │ Ecosystem    │
  ├─────────────┼─────────────────────┼──────────────┤
  │ libxml2     │ 2.9.0 — 2.9.14     │ C/System     │
  │ lxml        │ < 4.9.3             │ PyPI         │
  │ nokogiri    │ < 1.15.4            │ RubyGems     │
  │ libxml2-dev │ 2.9.0 — 2.9.14     │ apt/deb      │
  └─────────────┴─────────────────────┴──────────────┘

  If you parse XML from untrusted sources and use any of the above
  at the listed versions, you are affected.

🛡️ HOW TO PATCH SAFELY
  Primary fix:
    • Upgrade libxml2 to >= 2.9.15
    • Ubuntu/Debian: sudo apt update && sudo apt upgrade libxml2
    • macOS: brew upgrade libxml2
    • Python (lxml): pip install lxml>=4.9.3
    • Ruby (nokogiri): bundle update nokogiri

  ⚠️  Breaking changes: None reported in 2.9.15.

  Workaround (if you can't patch immediately):
    • Disable entity expansion: set XML_PARSE_NOENT flag to OFF
    • Validate/sanitize XML input before parsing
    • Use a WAF rule to block deeply nested entity references

✅ WHAT TO TEST
  After patching, verify:

  1. Check version:
     $ xmllint --version
     → Should show "20915" or higher

  2. Run the PoC (in a sandbox):
     $ python poc.py --target localhost
     → Should return "Not vulnerable" / connection refused

  3. Test your XML parsing still works:
     $ run your existing XML test suite
     → All tests should pass (no breaking changes)

  4. Monitor logs for 24h:
     → No new segfaults or XML parsing errors

╭──────────────────────────────────────────────────────────────╮
│  Sources: NVD, GitHub Advisory GHSA-xxxx-yyyy, OSV.dev       │
│  Cached: 2026-01-20 14:32 UTC │ Refresh: sentinel cve       │
│  CVE-2026-12345 --no-cache                                   │
╰──────────────────────────────────────────────────────────────╯
```

### Example: `sentinel scan ./my-project --cve CVE-2026-12345`

```
╭──────────────────────────────────────────────────────────────╮
│  🛡️  SENTINEL SCAN — ./my-project                           │
│  Checking: CVE-2026-12345                                    │
╰──────────────────────────────────────────────────────────────╯

  Project type: Python (pyproject.toml + requirements.txt)
  Dependencies found: 142 (12 direct, 130 transitive)

  Scanning for CVE-2026-12345 (libxml2 buffer overflow)...

  🔴 AFFECTED

  ┌─────────────┬──────────────┬─────────────────┬────────────┐
  │ Dependency  │ Your Version │ Affected Range  │ Fix Version│
  ├─────────────┼──────────────┼─────────────────┼────────────┤
  │ lxml        │ 4.9.1        │ < 4.9.3         │ >= 4.9.3   │
  └─────────────┴──────────────┴─────────────────┴────────────┘

  Impact: lxml 4.9.1 bundles libxml2 2.9.12, which is vulnerable.

  📋 Remediation:
     pip install lxml>=4.9.3
     # or update requirements.txt: lxml>=4.9.3
```

### Example: `sentinel scan ./my-project --cve CVE-2026-12345 --deep`

```
  ... (same header as above) ...

  🟡 POTENTIALLY AFFECTED

  lxml 4.9.1 is in your dependencies (vulnerable version).

  Code analysis:
    • lxml imported in 3 files:
      - src/feed_parser.py (line 12): from lxml import etree
      - src/sitemap.py (line 5): from lxml.html import parse
      - tests/test_xml.py (line 3): from lxml import etree

    • Vulnerable function (xmlParseAttValueComplex) is triggered by:
      etree.parse() and etree.fromstring() with entity expansion enabled.

    • src/feed_parser.py: etree.fromstring(untrusted_input) on line 45
      ⚠️  Parses external RSS feeds — UNTRUSTED INPUT

    • src/sitemap.py: parses local sitemaps only — lower risk

  Verdict: LIKELY AFFECTED — src/feed_parser.py parses untrusted XML
  using a vulnerable lxml version without disabling entity expansion.

  📋 Recommended fix:
     1. pip install lxml>=4.9.3
     2. Add parser hardening in feed_parser.py:
        parser = etree.XMLParser(resolve_entities=False)
        etree.fromstring(data, parser=parser)
```

### Example: `sentinel scan ./my-project` (full scan, no specific CVE)

```
╭──────────────────────────────────────────────────────────────╮
│  🛡️  SENTINEL SCAN — ./my-project                           │
│  Full vulnerability scan                                     │
╰──────────────────────────────────────────────────────────────╯

  Project type: Node.js (package-lock.json)
  Dependencies found: 847 (34 direct, 813 transitive)

  Querying OSV.dev for known vulnerabilities...

  Found 5 vulnerabilities:

  🔴 CRITICAL (1)
  ┌──────────────────┬──────────┬──────────────┬──────────────┐
  │ CVE              │ Package  │ Your Version │ Fix          │
  ├──────────────────┼──────────┼──────────────┼──────────────┤
  │ CVE-2026-12345   │ xml2js   │ 0.4.19       │ >= 0.5.0     │
  └──────────────────┴──────────┴──────────────┴──────────────┘

  🟠 HIGH (2)
  ┌──────────────────┬──────────┬──────────────┬──────────────┐
  │ CVE-2026-11111   │ lodash   │ 4.17.20      │ >= 4.17.21   │
  │ CVE-2026-22222   │ axios    │ 0.21.1       │ >= 0.21.2    │
  └──────────────────┴──────────┴──────────────┴──────────────┘

  🟡 MEDIUM (1)
  ┌──────────────────┬──────────────┬──────────┬─────────────┐
  │ CVE-2026-33333   │ json5        │ 2.2.1    │ >= 2.2.2    │
  └──────────────────┴──────────────┴──────────┴─────────────┘

  🟢 LOW (1)
  ┌──────────────────┬──────────────┬──────────┬─────────────┐
  │ CVE-2026-44444   │ semver       │ 7.3.7    │ >= 7.3.8    │
  └──────────────────┴──────────────┴──────────┴─────────────┘

  Run `sentinel cve <CVE-ID>` for details on any vulnerability.
  Run `sentinel scan . --cve <CVE-ID> --deep` for code-path analysis.
```

### Example: `sentinel cve CVE-2026-12345 --json`

```json
{
  "cve_id": "CVE-2026-12345",
  "cvss_score": 9.8,
  "cvss_severity": "Critical",
  "published": "2026-01-15",
  "last_modified": "2026-01-18",
  "sections": {
    "what_it_is": "A heap-based buffer overflow in libxml2's xmlParseAttValueComplex() function...",
    "how_to_exploit": {
      "attack_vector": "Network",
      "complexity": "Low",
      "authentication_required": false,
      "difficulty": "Trivial",
      "poc_available": true,
      "poc_url": "https://github.com/researcher/CVE-2026-12345-poc",
      "summary": "Any application that parses untrusted XML using libxml2..."
    },
    "who_should_panic": {
      "affected_packages": [
        {
          "name": "libxml2",
          "ecosystem": "C/System",
          "affected_versions": "2.9.0 — 2.9.14",
          "fixed_version": "2.9.15"
        },
        {
          "name": "lxml",
          "ecosystem": "PyPI",
          "affected_versions": "< 4.9.3",
          "fixed_version": "4.9.3"
        }
      ]
    },
    "how_to_patch": {
      "primary_fix": "Upgrade libxml2 to >= 2.9.15",
      "commands": {
        "debian": "sudo apt update && sudo apt upgrade libxml2",
        "macos": "brew upgrade libxml2",
        "python": "pip install lxml>=4.9.3"
      },
      "breaking_changes": null,
      "workarounds": ["Disable entity expansion", "Validate XML input"]
    },
    "what_to_test": [
      "Check version: xmllint --version (should show 20915+)",
      "Run existing XML test suite",
      "Monitor logs for 24h for segfaults"
    ]
  },
  "sources": ["NVD", "GHSA-xxxx-yyyy", "OSV.dev"],
  "cached_at": "2026-01-20T14:32:00Z"
}
```

---

## 9. Security & Privacy

### Data Flow Concerns

| Data | Where it goes | Risk | Mitigation |
|---|---|---|---|
| CVE IDs | NVD, OSV, GitHub APIs | None (public data) | — |
| Dependency lists | Claude API | Low (package names/versions only) | `--local` mode skips Claude |
| Source code snippets | Claude API (in `--deep` mode) | **Medium** — proprietary code sent to API | Opt-in only; `--local` flag; clear docs |
| API keys | Local config file | Standard | `chmod 600 ~/.sentinel/config.toml` |

### Privacy Modes

1. **Default mode**: Sends CVE data + dependency list to Claude. No source code.
2. **Deep mode** (`--deep`): Sends relevant source code snippets to Claude. Opt-in only.
3. **Local mode** (`--local`): No data sent to Claude. Dependency matching only (no AI-generated explanations, uses cached/raw CVE descriptions).

### API Key Management

```toml
# ~/.sentinel/config.toml
[api_keys]
anthropic = "sk-ant-..."     # Required for AI analysis
nvd = "xxxxxxxx-xxxx-..."    # Optional, increases rate limit from 5/30s to 50/30s
github = "ghp_..."           # Optional, for GHSA GraphQL API

[privacy]
default_mode = "standard"     # standard | deep | local
send_code = false             # Extra guard: must be true for --deep to work
```

### Rate Limiting

- NVD: 5 req/30s without key, 50 req/30s with key
- OSV.dev: No key required, generous limits
- Claude: Per Anthropic plan limits
- Local cache reduces API calls significantly

---

## 9b. K8s Runtime BOM Scanner — Security

### Data Flow

| Data | Where it goes | Risk | Mitigation |
|---|---|---|---|
| K8s pod metadata | Local only | None | Read-only RBAC, never writes to cluster |
| Image names | Local + container runtime | Low | Credential redaction in logs |
| Package lists from images | Local → OSV API for vuln check | Low | Only package names/versions, no image content |
| Registry credentials | Never stored/logged | None | Redacted from all log output |

### Access Controls
- Read-only ClusterRole: only `get` and `list` on pods, namespaces, deployments
- Never execs into running pods
- Never writes to cluster
- Detects in-cluster vs kubeconfig automatically
- Credentials never cached or stored

### Container Runtime Security
- Uses `--rm` flag on all container runs (cleanup)
- Overrides entrypoint only for package listing commands
- No volume mounts from host
- Timeout on all container operations (120s)

## 9c. Execution Path Analysis — Security

### CRITICAL: No Source Code Sent Externally

| Data | Sent to Claude? | Notes |
|---|---|---|
| Source code | **NEVER** | Enforced by assertion + `contains_source_code()` check |
| Function names | Yes (sanitized) | Only names, never bodies |
| Import names | Yes (sanitized) | Module and imported name only |
| Call graph edges | Yes (sanitized) | `caller -> callee` pairs only |
| File names | Yes (sanitized) | Base filenames only |
| Line numbers | Yes (sanitized) | Just numbers |
| CVE description | Yes | Public data from NVD/OSV |

### Enforcement
- `SanitizedContext` class strips all source code
- `contains_source_code()` heuristic checks for code patterns
- `assert not contains_source_code(context)` before every API call — raises AssertionError if violated
- `audit_log()` writes everything sent to Claude to `~/.sentinel/audit.log`
- `--local-only` flag disables all external communication

### Audit Trail
All Claude API calls are logged with:
- Timestamp
- Exact data sent (function names, edges, etc.)
- Action type
Written to `~/.sentinel/audit.log` in JSON-lines format.

## 10. Implementation Phases

### Phase 1: CVE Explainer CLI (Weeks 1–3)

**Goal**: `sentinel cve CVE-2026-12345` works end-to-end.

| Task | Est. |
|---|---|
| Project scaffolding (pyproject.toml, CLI skeleton with click) | 2h |
| NVD API fetcher | 4h |
| OSV.dev API fetcher | 3h |
| GitHub Advisory DB fetcher | 4h |
| Claude synthesizer (prompt engineering, 5-section output) | 6h |
| Rich terminal output renderer | 4h |
| JSON + Markdown output formatters | 2h |
| SQLite caching layer | 3h |
| Config management (~/.sentinel/config.toml) | 2h |
| Error handling, retries, timeouts | 3h |
| Tests + fixtures (mock API responses) | 4h |
| README + basic docs | 2h |
| **Total** | **~39h** |

**Deliverable**: Working `sentinel cve` command with all 5 sections, caching, multiple output formats.

### Phase 2: Repo Dependency Scanner (Weeks 4–5)

**Goal**: `sentinel scan ./repo` detects vulnerable dependencies.

| Task | Est. |
|---|---|
| Dependency parser framework (base class, registry) | 3h |
| Node.js parser (package.json, package-lock.json, yarn.lock) | 4h |
| Python parser (requirements.txt, pyproject.toml, Pipfile.lock) | 4h |
| Go parser (go.mod, go.sum) | 3h |
| Rust parser (Cargo.toml, Cargo.lock) | 3h |
| Java parser (pom.xml) | 3h |
| Ruby parser (Gemfile.lock) | 2h |
| OSV.dev batch query for full scans | 3h |
| Version range matching logic | 4h |
| Scan output formatting | 3h |
| GitHub URL cloning | 2h |
| Tests with real-world lockfiles | 4h |
| **Total** | **~38h** |

**Deliverable**: `sentinel scan` with dependency-level CVE detection across major ecosystems.

### Phase 3: Deep Repo Analysis (Weeks 6–7)

**Goal**: `sentinel scan ./repo --cve X --deep` does code-path analysis.

| Task | Est. |
|---|---|
| Source file discovery (find imports of affected packages) | 4h |
| Import/usage extraction per language (Python, JS, Go, Rust) | 8h |
| Claude code-analysis prompt engineering | 6h |
| Context window management (relevant snippets only) | 4h |
| Verdict logic (Affected / Potentially / Not Affected) | 3h |
| Privacy controls (--local flag, send_code config) | 2h |
| Tests | 4h |
| **Total** | **~31h** |

**Deliverable**: AI-powered code-path analysis telling you if vulnerable functions are actually called.

### Phase 4: Telegram Integration via OpenClaw (Week 8)

**Goal**: `sentinel CVE-2026-12345` in Telegram returns the report.

| Task | Est. |
|---|---|
| OpenClaw command handler (pattern matching in agent config) | 3h |
| Output formatting for Telegram (markdown, char limits, message splitting) | 4h |
| GitHub URL repo scan via Telegram | 3h |
| Error handling (timeouts, long-running scans) | 2h |
| Testing in live Telegram chat | 2h |
| **Total** | **~14h** |

**Deliverable**: Full Sentinel functionality accessible via Telegram messages.

### Phase 5: Watch/Monitor Feature (Week 9)

**Goal**: `sentinel watch CVE-2026-12345` monitors for updates.

| Task | Est. |
|---|---|
| Watch registry (SQLite table of watched CVEs) | 2h |
| Background polling daemon / cron integration | 4h |
| Diff detection (compare cached vs fresh CVE data) | 3h |
| Notification system (terminal alert, optional Telegram ping) | 3h |
| `sentinel watch --list`, `--stop` commands | 2h |
| Tests | 2h |
| **Total** | **~16h** |

**Deliverable**: Persistent CVE monitoring with update notifications.

---

### Total Estimated Effort

| Phase | Hours | Timeline |
|---|---|---|
| Phase 1: CVE Explainer | ~39h | Weeks 1–3 |
| Phase 2: Dependency Scanner | ~38h | Weeks 4–5 |
| Phase 3: Deep Analysis | ~31h | Weeks 6–7 |
| Phase 4: Telegram Integration | ~14h | Week 8 |
| Phase 5: Watch Feature | ~16h | Week 9 |
| **Total** | **~138h** | **~9 weeks** |

---

## Appendix: Quick Start (Post-Implementation)

```bash
# Install
pip install sentinel-cve

# Configure
sentinel config set api-key sk-ant-...

# Explain a CVE
sentinel cve CVE-2026-12345

# Scan your project
sentinel scan . --cve CVE-2026-12345

# Full vulnerability scan
sentinel scan .

# Deep analysis
sentinel scan . --cve CVE-2026-12345 --deep

# Watch for updates
sentinel watch CVE-2026-12345

# In Telegram
# Just message: sentinel CVE-2026-12345

# Persona-based output formatting
sentinel cve CVE-2026-12345 --format exec       # Executive/CISO: 10-second traffic light summary
sentinel cve CVE-2026-12345 -f engineer          # Engineer: deep technical dive with commands
sentinel cve CVE-2026-12345 -f devops            # DevOps/SRE: infrastructure, containers, K8s
sentinel cve CVE-2026-12345 -f security          # Security analyst: default 5-section report
sentinel scan . --cve CVE-2026-12345 -f exec     # Works with scan too
```

---

## 11. Persona-Based Output Formatting

### Overview

Sentinel supports four output personas via the `--format` / `-f` flag, each tailored to a different audience. The same CVE data is analyzed by Claude with a persona-specific prompt, producing output focused on what that audience cares about most.

### Personas

| Persona | Audience | Focus | Length |
|---|---|---|---|
| `security` | Security Analyst | 5-section vulnerability briefing (What/Exploit/Panic/Patch/Test) | Full report |
| `exec` | CISO / Executive | Traffic light severity, business impact, one action item | 5-10 lines |
| `engineer` | Software Engineer | Exact versions, upgrade commands, grep patterns, breaking changes | Detailed |
| `devops` | DevOps / SRE | Infrastructure impact, containers, K8s, monitoring, incident response | Detailed |

### Implementation Details

- **Prompts**: Each persona has a dedicated system prompt and user prompt template in `sentinel/prompts.py`
- **Synthesizer**: `analyze_cve()` accepts a `persona` parameter, selects the right prompt, and parses response sections accordingly
- **Caching**: Results are cached per-persona — same CVE with different `--format` produces and caches different analyses
- **Rendering**: Terminal, Slack, Teams, Telegram, and plain text formatters all support persona-specific section layouts
- **Default**: `--format security` produces identical output to the original (no flag) behavior

### Cache Keys

Cache keys include the persona to avoid mixing outputs:
- `analysis:CVE-2024-3094:security` — security analyst report
- `analysis:CVE-2024-3094:exec` — executive summary
- `analysis:CVE-2024-3094:engineer` — engineer advisory
- `analysis:CVE-2024-3094:devops` — devops/SRE advisory
- `analysis:CVE-2024-3094:brief` — brief one-paragraph (persona-independent)
