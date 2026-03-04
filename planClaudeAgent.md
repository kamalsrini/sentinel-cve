# Sentinel + Claude Code Agent Mode — Plan

## Overview

Add Claude Code as an **optional local agent backend** for Sentinel. Instead of the current approach (fetch data → build prompt → send to Claude API → parse response), Claude Code runs locally as an autonomous agent that can read files, run commands, and reason through the codebase directly.

**Key principle:** This is an **additive option** (`--agent`), not a replacement. The existing Claude API mode remains the default.

```
sentinel cve CVE-2024-3094                          # Default: Claude API (existing)
sentinel cve CVE-2024-3094 --agent                  # New: Claude Code agent
sentinel scan ./repo --cve CVE-2024-3094 --agent    # Agent reads repo directly
sentinel scan --k8s --agent                         # Agent runs kubectl itself
```

---

## Why Claude Code Agent?

| Capability | Claude API (current) | Claude Code Agent |
|---|---|---|
| Read repo files | ❌ We extract & send metadata | ✅ Reads directly, navigates freely |
| Run system commands | ❌ We run, send output | ✅ Runs `dpkg -l`, `npm audit`, `pip show`, `kubectl` |
| Trace code paths | ❌ We build AST call graph | ✅ Reads imports, follows calls, understands context |
| Multi-step investigation | ❌ Single request/response | ✅ Iterates: check file → follow import → read function → verdict |
| Verify fixes | ❌ | ✅ Runs tests, checks versions, confirms patch applied |
| Source code safety | ⚠️ We must sanitize | ✅ Code stays local — Claude Code runs on-machine |
| Internet research | ❌ We pre-fetch CVE data | ✅ Can fetch NVD/OSV/advisories itself |
| Offline mode | ❌ Needs API | ❌ Needs API (but code stays local) |

### The Big Win: Deep Scan Without Sanitization Overhead

Currently, `--execution-path` requires complex AST parsing, call graph construction, and careful sanitization before sending metadata to Claude. With agent mode, Claude Code simply **reads the code and traces the path itself** — no sanitization needed because the code never leaves the machine.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    sentinel CLI                           │
│                                                          │
│  sentinel cve CVE-XXXX         sentinel cve CVE-XXXX     │
│  (default: API mode)           --agent (agent mode)      │
│         │                              │                 │
│         ▼                              ▼                 │
│  ┌──────────────┐            ┌──────────────────┐        │
│  │ Claude API   │            │ Claude Code      │        │
│  │ (existing)   │            │ Agent Runner     │        │
│  │              │            │                  │        │
│  │ fetch data   │            │ spawns `claude`  │        │
│  │ build prompt │            │ with structured  │        │
│  │ parse resp   │            │ task prompt      │        │
│  └──────────────┘            │                  │        │
│                              │ agent reads repo │        │
│                              │ runs commands    │        │
│                              │ fetches CVE data │        │
│                              │ returns findings │        │
│                              └──────────────────┘        │
│                                       │                  │
│                                       ▼                  │
│                              ┌──────────────────┐        │
│                              │ Output Parser    │        │
│                              │ (structured JSON │        │
│                              │  from agent)     │        │
│                              └──────────────────┘        │
│                                       │                  │
│                                       ▼                  │
│                              ┌──────────────────┐        │
│                              │ Renderer         │        │
│                              │ (existing —      │        │
│                              │  same output)    │        │
│                              └──────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

---

## Implementation

### 1. Agent Runner (`sentinel/agent_runner.py`)

Core module that invokes Claude Code as a subprocess:

```python
class AgentRunner:
    """Runs Claude Code as a local agent for Sentinel tasks."""
    
    def __init__(self, workdir: str = "."):
        self.workdir = workdir
        self.claude_bin = shutil.which("claude")
    
    def is_available(self) -> bool:
        """Check if Claude Code is installed."""
        return self.claude_bin is not None
    
    def run_task(self, prompt: str, timeout: int = 300) -> AgentResult:
        """Run a structured task via Claude Code.
        
        Uses `claude -p <prompt> --output-format json` for structured output.
        Runs in the target repo directory so agent has full access.
        """
        ...
    
    def explain_cve(self, cve_id: str, persona: str = "security") -> dict:
        """Agent researches and explains a CVE."""
        ...
    
    def scan_repo(self, repo_path: str, cve_id: str = None) -> dict:
        """Agent scans a repo for vulnerabilities."""
        ...
    
    def deep_scan(self, repo_path: str, cve_id: str) -> dict:
        """Agent traces execution paths in the codebase."""
        ...
    
    def scan_k8s(self, namespace: str = None, cve_id: str = None) -> dict:
        """Agent runs kubectl to inspect cluster."""
        ...
```

### 2. Invocation Method

Claude Code supports a non-interactive print mode:

```bash
# Structured task with JSON output
claude -p "Your task prompt" --output-format json

# With specific working directory (for repo scanning)
cd /path/to/repo && claude -p "Analyze this codebase for CVE-2024-3094 impact"
```

**How Sentinel calls it:**
```python
result = subprocess.run(
    ["claude", "-p", task_prompt, "--output-format", "json"],
    capture_output=True, text=True, timeout=300,
    cwd=repo_path,  # Agent wakes up in the target repo
)
```

### 3. Task Prompts

Each Sentinel command maps to a structured agent prompt:

#### CVE Explain (`sentinel cve CVE-XXXX --agent`)
```
You are a security analyst. Research and explain CVE-{cve_id}.

Steps:
1. Fetch the CVE from NVD: curl https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}
2. Fetch from OSV: curl https://api.osv.dev/v1/vulns/{cve_id}
3. Search for exploit information and patches

Output your findings as JSON with this exact structure:
{
  "sections": {
    "what_it_is": "...",
    "how_to_exploit": "...",
    "who_should_panic": "...",
    "how_to_patch": "...",
    "what_to_test": "..."
  },
  "cvss": "...",
  "severity": "...",
  "sources": ["url1", "url2"]
}

Persona: {persona}
[persona-specific instructions appended]
```

#### Repo Scan (`sentinel scan ./repo --cve CVE-XXXX --agent`)
```
You are a security analyst. Analyze this repository for impact from CVE-{cve_id}.

Steps:
1. Read dependency files (package.json, requirements.txt, go.mod, build.gradle, Podfile, etc.)
2. Identify if any dependency matches the CVE's affected packages
3. If affected, trace whether the vulnerable function is actually called:
   - Find imports of the affected package
   - Trace from entry points to vulnerable functions
   - Check if vulnerable code paths are reachable
4. Check current versions against patched versions

Output as JSON:
{
  "status": "AFFECTED|NOT_AFFECTED|POTENTIALLY_AFFECTED",
  "affected_dependency": {"name": "...", "version": "...", "ecosystem": "..."},
  "execution_path": {"reachable": bool, "chain": ["file:line → file:line → ..."]},
  "remediation": {"upgrade_to": "...", "commands": ["..."]},
  "confidence": "high|medium|low",
  "reasoning": "..."
}
```

#### K8s Scan (`sentinel scan --k8s --agent`)
```
You are a security analyst. Scan this Kubernetes cluster for vulnerabilities.

Steps:
1. Run: kubectl get pods --all-namespaces -o json
2. Extract all unique container images
3. For each image, check installed packages:
   - Run: docker run --rm --entrypoint /bin/sh <image> -c "dpkg -l 2>/dev/null || apk list 2>/dev/null || rpm -qa 2>/dev/null"
4. Cross-reference packages against known CVEs via OSV API
5. Group findings by namespace and severity

Output as JSON:
{
  "cluster_scan": {
    "total_images": N,
    "affected_images": N,
    "findings": [
      {"namespace": "...", "pod": "...", "image": "...", "cves": [...]}
    ]
  }
}
```

### 4. Output Parsing

Agent returns JSON that maps directly to Sentinel's existing data structures:

```python
def parse_agent_output(raw_output: str) -> dict:
    """Parse Claude Code's JSON output into Sentinel format.
    
    Handles:
    - Clean JSON responses
    - JSON embedded in markdown code blocks
    - Partial responses (agent timed out)
    - Error responses
    """
    # Extract JSON from output (may be wrapped in ```json blocks)
    # Validate required fields
    # Map to existing Sentinel data structures
    ...
```

Once parsed, the output flows through the **existing renderer** — same terminal output, same Slack/Teams formatting, same persona support.

### 5. CLI Changes

```python
# Add --agent flag to existing commands
@click.option("--agent", is_flag=True, help="Use Claude Code agent (local, reads code directly)")

# In command handlers:
if agent:
    runner = AgentRunner(workdir=repo_path)
    if not runner.is_available():
        click.echo("Error: Claude Code not installed. Install: npm install -g @anthropic-ai/claude-code")
        sys.exit(1)
    result = runner.explain_cve(cve_id, persona=format)
else:
    # Existing API flow
    result = analyze_cve(cve_id, persona=format)
```

### 6. Configuration

```bash
# Config options
sentinel config set agent-mode claude-code    # or "api" (default)
sentinel config set agent-timeout 300         # seconds
sentinel config set agent-model opus          # which model Claude Code uses

# Environment variables
SENTINEL_AGENT_MODE=claude-code
CLAUDE_CODE_PATH=/usr/local/bin/claude        # custom path
```

---

## Security Considerations

### Why Agent Mode Is Actually More Secure for Code Analysis

1. **Source code never leaves the machine** — Claude Code runs locally, processes code locally
2. **No sanitization needed** — we don't need to strip code from prompts because there's no external API call
3. **Full context** — agent sees the real codebase, not lossy metadata
4. **Audit trail** — Claude Code logs all tool use to `~/.claude/logs/`

### Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Agent runs arbitrary commands | Claude Code has built-in permission model — asks before executing |
| Agent modifies files | Use `--read-only` flag in Sentinel's prompt instructions |
| Agent accesses network | Acceptable — needs to fetch CVE data from NVD/OSV |
| Long-running agents | Configurable timeout (default 300s), auto-kill on timeout |
| Claude Code not installed | Graceful error with install instructions |
| Output parsing fails | Fallback to raw text rendering |

### Permission Model

Sentinel's agent prompts explicitly instruct Claude Code:
- ✅ READ files in the target directory
- ✅ RUN read-only commands (`dpkg -l`, `npm list`, `pip show`, `kubectl get`)
- ✅ FETCH from NVD/OSV APIs via curl
- ❌ DO NOT modify any files
- ❌ DO NOT install packages
- ❌ DO NOT run destructive commands

---

## Comparison: When to Use Each Mode

| Scenario | Recommended Mode | Why |
|---|---|---|
| Quick CVE lookup | API (`default`) | Faster, no local tools needed |
| Shallow dependency check | API (`default`) | Just matches versions, fast |
| Deep code-path analysis | Agent (`--agent`) | Reads actual code, traces imports |
| Repo security audit | Agent (`--agent`) | Multi-step investigation, runs tools |
| K8s cluster scan | Agent (`--agent`) | Runs kubectl, docker inspect directly |
| CI/CD pipeline | API (`default`) | Deterministic, no agent overhead |
| Air-gapped / offline | Neither (use `--local-only`) | No external calls at all |
| Server/API mode | API only | Agent requires local filesystem access |

---

## Implementation Phases

### Phase 1: Core Agent Runner (Week 1)
- [ ] `sentinel/agent_runner.py` — AgentRunner class
- [ ] Claude Code invocation via subprocess (`claude -p`)
- [ ] JSON output parsing with fallback handling
- [ ] `--agent` flag on `sentinel cve` command
- [ ] Timeout management and error handling
- [ ] Tests with mocked Claude Code responses

### Phase 2: Repo Scanning via Agent (Week 2)
- [ ] `--agent` flag on `sentinel scan` command
- [ ] Agent prompt for dependency analysis
- [ ] Agent prompt for execution path tracing (replaces AST parser)
- [ ] Output mapping to existing Sentinel data structures
- [ ] Side-by-side comparison tests (API vs agent produce equivalent output)

### Phase 3: K8s and Advanced Features (Week 3)
- [ ] `--agent` flag on `sentinel scan --k8s`
- [ ] Agent prompt for cluster scanning
- [ ] Multi-persona support in agent mode
- [ ] Agent-powered SBOM generation
- [ ] Configuration management (default mode, timeout, model)

### Phase 4: Polish (Week 4)
- [ ] Progress indicators for agent tasks
- [ ] Structured error reporting
- [ ] Documentation and README updates
- [ ] Performance benchmarking: API mode vs agent mode
- [ ] Integration with Slack/Teams (agent runs on server, posts results)

---

## Example User Experience

```bash
$ sentinel cve CVE-2024-3094 --agent
🤖 Starting Claude Code agent...
⏳ Agent researching CVE-2024-3094...
✅ Agent completed (23s)

╭──────────── 🔍 What it is ──────────────╮
│ XZ Utils versions 5.6.0-5.6.1 contain   │
│ a sophisticated supply chain backdoor... │
╰──────────────────────────────────────────╯
[... same 5-section output as API mode ...]

$ sentinel scan ./my-app --cve CVE-2024-3094 --agent
🤖 Starting Claude Code agent in ./my-app...
⏳ Agent reading dependencies...
⏳ Agent tracing code paths...
✅ Agent completed (45s)

🟢 NOT AFFECTED
  Dependency: xz-utils not found in requirements.txt or Pipfile
  Agent also checked: Dockerfile base image (python:3.11-slim → xz 5.4.1 ✅)
  Confidence: HIGH

$ sentinel scan ./my-app --cve CVE-2024-22195 --agent -f engineer
🤖 Starting Claude Code agent in ./my-app...
⏳ Agent reading source code...
⏳ Agent tracing jinja2.utils.urlize() usage...
✅ Agent completed (67s)

🔴 AFFECTED — REACHABLE
  Chain: app.py:12 → templates/render.py:45 → jinja2.utils.urlize()
  The vulnerable function is called when rendering user profile bios.
  
  📦 Upgrade: pip install jinja2>=3.1.3
  🧪 Test: python -c "import jinja2; print(jinja2.__version__)"
  ⚠️ Breaking: urlize() now escapes all HTML by default
```

---

## Dependencies

- **Required for agent mode:** Claude Code (`npm install -g @anthropic-ai/claude-code`)
- **Required for API mode:** `anthropic` Python package (existing)
- **No new Python dependencies** — agent is invoked via subprocess
