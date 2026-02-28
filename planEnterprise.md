# Sentinel Enterprise — Vulnerability Management at Scale

> **Document Type:** Product & Architecture Plan
> **Audience:** VP of Security, CISO, Engineering Leadership
> **Status:** Draft v1.0 — February 2026

---

## Executive Summary

Sentinel today is a CLI tool that answers: *"Does this CVE affect my project?"*

Enterprise security teams managing ~3,000 applications need a fundamentally different answer: *"Which of my 3,000 apps does this CVE affect, who owns them, what's the patch SLA, and are we on track?"*

This document defines **Sentinel Enterprise** — a centralized vulnerability management platform that integrates with ServiceNow CMDB as the single source of truth, automates CVE-to-asset correlation at scale, enforces SLA-driven remediation workflows, and provides audit-ready compliance reporting.

**Key outcomes:**
- Blast radius determination in seconds, not days
- SLA compliance tracking with automated escalation
- 80%+ reduction in manual triage effort via Claude-powered analysis
- Audit-ready remediation evidence chain
- Single pane of glass across 3,000+ applications

---

## Table of Contents

1. [Problem Restatement](#1-problem-restatement)
2. [Architecture — Sentinel Enterprise](#2-architecture--sentinel-enterprise)
3. [ServiceNow Integration (Deep)](#3-servicenow-integration-deep)
4. [CVE-to-Asset Correlation Engine](#4-cve-to-asset-correlation-engine)
5. [SLA Management & Escalation](#5-sla-management--escalation)
6. [Remediation Workflow](#6-remediation-workflow)
7. [Reporting & Compliance](#7-reporting--compliance)
8. [Handling SaaS Applications](#8-handling-saas-applications)
9. [Tech Stack for Enterprise](#9-tech-stack-for-enterprise)
10. [Implementation Phases](#10-implementation-phases)
11. [What Sentinel CLI Becomes](#11-what-sentinel-cli-becomes)
12. [Competitive Landscape](#12-competitive-landscape)

---

## 1. Problem Restatement

### The Gap Between CLI and Enterprise Reality

The current Sentinel CLI was designed for a developer sitting in a single repository asking *"Am I affected by CVE-2024-XXXX?"* This model breaks down completely in enterprise environments:

| Dimension | Sentinel CLI (Today) | Enterprise Reality |
|---|---|---|
| **Scope** | 1 repo at a time | ~3,000 applications |
| **Asset source** | `package.json`, `go.mod`, etc. | ServiceNow CMDB |
| **Tech stack** | What's in the repo | Homegrown + SaaS + COTS + legacy |
| **Ownership** | The developer running it | Distributed across dozens of teams |
| **Tracking** | One-shot analysis | Continuous SLA-driven lifecycle |
| **Output** | Terminal report | Tickets, dashboards, compliance evidence |
| **Question** | "Am I affected?" | "Who's affected, who owns it, are we compliant?" |

### The Real Bottleneck

Finding CVEs is not the hard part. NVD publishes them. Scanners find them. The bottleneck is everything that happens *after*:

```
CVE Published
    │
    ├── Which of our 3,000 apps are affected?        ← CORRELATION
    ├── Who owns each affected app?                   ← OWNERSHIP
    ├── What's the SLA for each finding?              ← POLICY
    ├── Has remediation started?                      ← TRACKING
    ├── Is the SLA about to breach?                   ← ESCALATION
    ├── Can we prove it's patched?                    ← VERIFICATION
    └── Can we show auditors the full timeline?       ← COMPLIANCE
```

**Every one of these steps is manual today.** Sentinel Enterprise automates the entire chain.

### ServiceNow CMDB Is the Authority

In this environment, the CMDB is the canonical source for:
- Application inventory and metadata
- Business criticality tiers
- Technology stack declarations
- Ownership and team assignments
- Environment mappings (prod, staging, dev)
- Dependency relationships between CIs

Sentinel Enterprise treats CMDB as ground truth. It does not try to replace it — it enriches it with vulnerability intelligence.

---

## 2. Architecture — Sentinel Enterprise

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SENTINEL ENTERPRISE                              │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  CVE Ingest   │  │  Correlation │  │  SLA Engine   │  │ Remediation│ │
│  │  Engine       │  │  Engine      │  │               │  │ Tracker    │ │
│  │              │  │              │  │              │  │            │ │
│  │ • NVD        │  │ • CPE Match  │  │ • Policy     │  │ • States   │ │
│  │ • OSV        │──▶│ • SBOM Match │──▶│ • Deadlines  │──▶│ • Tickets  │ │
│  │ • CISA KEV   │  │ • Confidence │  │ • Escalation │  │ • Evidence │ │
│  │ • Vendor     │  │ • Blast      │  │ • Exceptions │  │ • Verify   │ │
│  │   Advisories │  │   Radius     │  │              │  │            │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘ │
│         │                 │                  │                │         │
│         └────────────┬────┴──────────────────┴────────────────┘         │
│                      │                                                  │
│              ┌───────▼────────┐         ┌──────────────────┐           │
│              │   PostgreSQL    │         │  Risk Dashboard   │           │
│              │   + Redis       │────────▶│  + API Layer      │           │
│              │   + Elastic     │         │  + Notifications  │           │
│              └───────┬────────┘         └──────────────────┘           │
│                      │                           │                      │
└──────────────────────┼───────────────────────────┼──────────────────────┘
                       │                           │
            ┌──────────▼──────────┐     ┌──────────▼──────────┐
            │   ServiceNow CMDB    │     │   Consumers          │
            │                      │     │                      │
            │ ◀── Pull: Apps,      │     │ • Web Dashboard      │
            │     Owners, CIs,     │     │ • Slack/Teams Bot    │
            │     Tech Stacks      │     │ • CI/CD Gates        │
            │                      │     │ • ServiceNow Portal  │
            │ ──▶ Push: Findings,  │     │ • Executive Reports  │
            │     Tickets, SLA     │     │ • Sentinel CLI       │
            │     Status           │     │                      │
            └──────────────────────┘     └──────────────────────┘
```

### Core Components

#### 2.1 Sentinel Server

The central service orchestrating everything. Stateless application tier behind a load balancer, horizontally scalable.

**Responsibilities:**
- API gateway for all consumers (dashboard, CLI, bots, CI/CD)
- Orchestrates CVE ingestion → correlation → SLA → remediation pipeline
- Manages authentication, authorization, and audit logging
- Serves real-time dashboard via WebSocket subscriptions

#### 2.2 CVE Ingestion Engine

Continuously monitors vulnerability sources and normalizes data into a unified format.

```
┌───────────────────────────────────────────────┐
│              CVE Ingestion Pipeline            │
│                                                │
│  NVD ─────┐                                   │
│  OSV ─────┤                                   │
│  CISA KEV ┼──▶ Normalize ──▶ Deduplicate ──▶ │
│  GHSA ────┤       │              │            │
│  Vendor ──┘       ▼              ▼            │
│              Unified CVE    Enrichment         │
│              Record         • EPSS score       │
│                             • Exploit maturity │
│                             • CISA KEV flag    │
│                             • Vendor patches   │
│                                                │
│              ──▶ Trigger Correlation ──▶       │
└───────────────────────────────────────────────┘
```

**Ingestion frequency:**
- NVD/OSV: Poll every 15 minutes
- CISA KEV: Poll every hour (small list, critical impact)
- Vendor advisories: Webhook where available, poll daily otherwise

**Volume estimates:**
- ~25,000 new CVEs/year (~70/day average)
- Most won't match the tech stack — correlation filters quickly
- Burst handling for mass disclosure events (e.g., Log4Shell)

#### 2.3 ServiceNow CMDB Integration

Bidirectional sync — detailed in [Section 3](#3-servicenow-integration-deep).

#### 2.4 SLA Engine

Policy-driven SLA calculation and enforcement — detailed in [Section 5](#5-sla-management--escalation).

#### 2.5 Remediation Tracker

Full lifecycle tracking per finding — detailed in [Section 6](#6-remediation-workflow).

#### 2.6 Risk Dashboard

Real-time operational and executive views — detailed in [Section 7](#7-reporting--compliance).

### Data Model

```
┌─────────────────────┐       ┌─────────────────────┐
│     Application      │       │        CVE           │
│─────────────────────│       │─────────────────────│
│ id (CMDB CI ID)      │       │ id (CVE-YYYY-NNNNN) │
│ name                 │       │ severity             │
│ owner_id             │       │ cvss_score           │
│ team_id              │       │ cvss_vector          │
│ tier (1/2/3)         │       │ epss_score           │
│ business_criticality │       │ affected_products[]  │
│ tech_stack[]         │       │ affected_versions[]  │
│ environments[]       │       │ cisa_kev (bool)      │
│ dependencies[]       │       │ exploit_available    │
│ cmdb_last_sync       │       │ exploit_maturity     │
│ sbom_available       │       │ patch_available      │
│ app_type (homegrown/ │       │ published_at         │
│   saas/cots)         │       │ sources[]            │
└──────────┬──────────┘       └──────────┬──────────┘
           │                              │
           │         ┌────────────────────┘
           │         │
           ▼         ▼
┌─────────────────────────────────┐
│           Finding                │
│─────────────────────────────────│
│ id                               │
│ cve_id ──────────────────────▶ CVE
│ application_id ──────────────▶ Application
│ status (enum)                    │
│ confidence_score (high/med/low)  │
│ sla_policy_id ───────────────▶ SLA Policy
│ sla_deadline                     │
│ sla_breach (bool)                │
│ assignee_id                      │
│ servicenow_incident_id           │
│ servicenow_change_id             │
│ created_at                       │
│ triaged_at                       │
│ assigned_at                      │
│ patched_at                       │
│ verified_at                      │
│ closed_at                        │
│ evidence[]                       │
│ notes[]                          │
│ exception_request_id             │
└─────────────────────────────────┘

┌─────────────────────────┐    ┌─────────────────────────┐
│       SLA Policy         │    │    Exception Request     │
│─────────────────────────│    │─────────────────────────│
│ id                       │    │ id                       │
│ cve_severity             │    │ finding_id               │
│ app_tier                 │    │ requested_by             │
│ deadline_hours           │    │ justification            │
│ cisa_kev_override (bool) │    │ mitigating_controls      │
│ created_at               │    │ new_deadline             │
│ updated_at               │    │ approved_by              │
│                          │    │ status (pending/         │
│                          │    │   approved/denied)       │
└─────────────────────────┘    └─────────────────────────┘
```

**Finding Status Lifecycle:**

```
New ──▶ Triaged ──▶ Assigned ──▶ In Progress ──▶ Patched ──▶ Verified ──▶ Closed
 │         │                                        │
 │         ├──▶ False Positive ──▶ Closed            │
 │         │                                        │
 │         └──▶ Exception Requested ──▶ Exception   │
 │              Approved/Denied                      │
 │                                                   │
 └──▶ Auto-Closed (CVE withdrawn/disputed)           │
                                                     │
                              Verification Failed ◀──┘
                                     │
                                     ▼
                              Back to In Progress
```

---

## 3. ServiceNow Integration (Deep)

### 3.1 CMDB Sync Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  CMDB Sync Service                        │
│                                                          │
│  ┌─────────────┐    ┌──────────────┐   ┌──────────────┐ │
│  │ Full Sync    │    │ Delta Sync    │   │ Push Service  │ │
│  │ (Nightly)    │    │ (Every 15m)   │   │ (Real-time)   │ │
│  │              │    │              │   │              │ │
│  │ Pull all CIs │    │ Pull changed │   │ Push findings│ │
│  │ Rebuild      │    │ CIs since    │   │ Create       │ │
│  │ app index    │    │ last sync    │   │ incidents    │ │
│  │              │    │              │   │ Update SLA   │ │
│  └──────┬───────┘    └──────┬───────┘   └──────┬───────┘ │
│         │                   │                   │         │
│         └───────────┬───────┘                   │         │
│                     ▼                           │         │
│         ┌──────────────────┐                    │         │
│         │ ServiceNow API    │◀───────────────────┘         │
│         │ (Table/CMDB API)  │                              │
│         │ OAuth 2.0         │                              │
│         └──────────────────┘                              │
└──────────────────────────────────────────────────────────┘
```

### 3.2 CMDB Data Extraction

**Configuration Items (CIs) we pull:**

| CI Class | What We Extract | Why |
|---|---|---|
| `cmdb_ci_appl` | Application name, owner, tier | Core app inventory |
| `cmdb_ci_server` | OS, installed software, IP | Infrastructure mapping |
| `cmdb_ci_docker_container` | Image, version, K8s namespace | Container scanning |
| `cmdb_ci_cloud_service_account` | Cloud provider, service type | Cloud resource mapping |
| `cmdb_ci_service` | Business service relationships | Dependency chains |
| `cmdb_ci_db_instance` | DB type, version | Database CVEs |
| `cmdb_software_instance` | Software name, version, install path | Package-level matching |

**Relationship mapping:**
```
ServiceNow Relationship          Sentinel Interpretation
─────────────────────────        ──────────────────────
App "Runs on" Server         →   App inherits server's OS CVEs
App "Uses" Database          →   App affected by DB CVEs
App "Depends on" Library     →   Direct dependency CVEs
Server "Contains" Software   →   Software instance CVEs affect server
```

**Sync implementation:**

```python
# Pseudocode: Delta sync using ServiceNow Table API
class CMDBSyncService:
    def delta_sync(self):
        last_sync = self.get_last_sync_timestamp()

        # Pull changed applications
        apps = self.snow_client.get_table(
            table='cmdb_ci_appl',
            query=f'sys_updated_on>{last_sync}',
            fields='sys_id,name,owned_by,u_business_tier,'
                   'u_tech_stack,operational_status'
        )

        # Pull changed software instances
        software = self.snow_client.get_table(
            table='cmdb_software_instance',
            query=f'sys_updated_on>{last_sync}',
            fields='sys_id,name,version,install_status,'
                   'installed_on'
        )

        # Pull changed relationships
        rels = self.snow_client.get_table(
            table='cmdb_rel_ci',
            query=f'sys_updated_on>{last_sync}',
            fields='parent,child,type'
        )

        # Upsert into Sentinel database
        self.upsert_applications(apps)
        self.upsert_software(software)
        self.upsert_relationships(rels)

        # Re-correlate affected applications against known CVEs
        self.trigger_recorrelation(changed_app_ids)
```

### 3.3 Incident & Change Request Creation

When a new finding is created, Sentinel automatically creates a ServiceNow incident:

```json
{
  "table": "incident",
  "data": {
    "short_description": "CVE-2024-3094 affects App: PaymentGateway (CRITICAL)",
    "description": "Sentinel has identified that CVE-2024-3094 (CVSS 10.0) affects the PaymentGateway application.\n\nAffected Component: xz-utils 5.6.0\nConfidence: HIGH (exact version match)\nSLA Deadline: 2024-04-01T14:00:00Z (24 hours)\n\nRemediation: Upgrade xz-utils to version 5.6.1 or later.\n\nSentinel Finding ID: FIND-2024-00847",
    "cmdb_ci": "sys_id_of_paymentgateway",
    "assigned_to": "sys_id_of_app_owner",
    "assignment_group": "sys_id_of_owning_team",
    "impact": "1",
    "urgency": "1",
    "category": "Security",
    "subcategory": "Vulnerability",
    "u_sentinel_finding_id": "FIND-2024-00847",
    "u_sentinel_cve_id": "CVE-2024-3094",
    "u_sentinel_sla_deadline": "2024-04-01T14:00:00Z"
  }
}
```

**Priority mapping (CVE Severity × App Tier):**

| | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| **Critical CVE** | P1 - Critical | P1 - Critical | P2 - High |
| **High CVE** | P1 - Critical | P2 - High | P3 - Moderate |
| **Medium CVE** | P2 - High | P3 - Moderate | P4 - Low |
| **Low CVE** | P3 - Moderate | P4 - Low | P4 - Low |

### 3.4 Authentication & Security

- **OAuth 2.0** client credentials grant with ServiceNow
- Dedicated **service account** with scoped ACLs:
  - Read: `cmdb_ci_*`, `cmdb_rel_ci`, `sys_user`, `sys_user_group`
  - Write: `incident`, `change_request`, `u_sentinel_*` custom tables
- **API rate limiting:** Respect ServiceNow rate limits (~500 req/min typical)
- **Data residency:** CMDB data cached locally is encrypted at rest (AES-256)
- **Audit trail:** Every CMDB read/write logged with timestamp and requesting service

---

## 4. CVE-to-Asset Correlation Engine

This is the hardest technical problem in the system. A CVE describes an affected product/package. CMDB describes infrastructure in business terms. Bridging the gap requires multiple matching strategies.

### 4.1 Correlation Pipeline

```
New CVE Arrives
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│                 Correlation Pipeline                      │
│                                                          │
│  Step 1: Extract affected products from CVE              │
│  ├── CPE URIs from NVD                                   │
│  ├── Package names from OSV/GHSA                         │
│  └── Product names from vendor advisory                  │
│                                                          │
│  Step 2: Match against CMDB index (parallel)             │
│  ├── CPE Matcher ──────────────▶ Matches[]              │
│  ├── Package Matcher ──────────▶ Matches[]              │
│  ├── SBOM Matcher ─────────────▶ Matches[]              │
│  └── Product Name Matcher ─────▶ Matches[]              │
│                                                          │
│  Step 3: Deduplicate & score confidence                  │
│  ├── Multiple matchers agree → HIGH confidence           │
│  ├── Single exact match → MEDIUM confidence              │
│  └── Fuzzy/name-only match → LOW confidence              │
│                                                          │
│  Step 4: Claude analysis (for LOW/MEDIUM confidence)     │
│  ├── "Is Spring Boot 2.7 affected by CVE in             │
│  │    spring-framework < 5.3.25?"                        │
│  └── Claude reasons about transitive dependencies        │
│                                                          │
│  Step 5: Generate findings                               │
│  └── Create Finding per (CVE, Application) pair          │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Matching Strategies

#### Strategy A: CPE Matching
The NVD assigns CPE (Common Platform Enumeration) URIs to CVEs. If CMDB software entries also have CPE identifiers:

```
CVE CPE:   cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*
           (versions < 5.3.25)

CMDB CI:   Software Instance "Spring Framework 5.3.20"
           CPE: cpe:2.3:a:vmware:spring_framework:5.3.20:*:*:*:*:*:*:*

Result:    MATCH — version 5.3.20 < 5.3.25 → AFFECTED (HIGH confidence)
```

**Limitation:** Many CMDB entries lack CPE data. This requires CMDB enrichment effort.

#### Strategy B: Package-Level Matching
For applications with SBOMs or package manifests tracked in CMDB:

```
CVE (from OSV):   Package "org.springframework:spring-core"
                  Versions [0, 5.3.25) and [6.0.0, 6.0.6)

SBOM (App X):     org.springframework:spring-core@5.3.20

Result:           MATCH — HIGH confidence
```

#### Strategy C: SBOM-Based Matching (CycloneDX / SPDX)
If applications generate SBOMs as part of CI/CD:

```
SBOM stored in Sentinel ──▶ Full dependency tree
CVE affected packages    ──▶ Search SBOM index

This catches transitive dependencies that CMDB won't track:
  App → Spring Boot 2.7 → spring-core 5.3.20 → AFFECTED
```

#### Strategy D: Product/Name Matching (Fuzzy)
Fallback when structured data is unavailable:

```
CVE mentions:     "Apache HTTP Server" versions < 2.4.58
CMDB CI:          Server "web-prod-01" has software "Apache/2.4.52"

Result:           MATCH — MEDIUM confidence (name match + version comparison)
```

#### Strategy E: Agent-Based Discovery
Lightweight agent deployed on servers reports actual installed packages:

```
Agent on web-prod-01 reports:
  httpd-2.4.52-1.el8.x86_64
  openssl-1.1.1k-7.el8_6.x86_64
  java-11-openjdk-11.0.17.0.8-2.el8_6.x86_64

These map precisely to CVEs → HIGH confidence
```

### 4.3 Confidence Scoring

| Confidence | Criteria | Action |
|---|---|---|
| **HIGH** | Exact version match via CPE, SBOM, or agent | Auto-create finding, start SLA clock |
| **MEDIUM** | Version range match or product-level match | Auto-create finding, flag for quick review |
| **LOW** | Name-only match, possible but uncertain | Create draft finding, require manual triage |

### 4.4 Blast Radius Calculation

When a new critical CVE arrives, the correlation engine immediately calculates blast radius:

```
CVE-2024-3094 (xz-utils backdoor)
├── Affected: xz-utils versions 5.6.0 and 5.6.1
│
├── CMDB Query: Which CIs have xz-utils 5.6.0 or 5.6.1?
│   ├── server-prod-01 (RHEL 9) → runs App: PaymentGateway (Tier 1)
│   ├── server-prod-02 (RHEL 9) → runs App: UserService (Tier 1)
│   ├── server-staging-01 (Fedora 40) → runs App: PaymentGateway-staging
│   └── container image base:fedora-40 → 47 containers in K8s
│
├── Blast Radius: 2 Tier 1 apps, 1 staging, 47 containers
├── Unique app owners to notify: 3
├── SLA: 24h (Critical CVE × Tier 1)
└── Auto-created: 2 P1 incidents, 1 P3 incident, 47 container findings
```

**Performance target:** Blast radius for any new CVE calculated within 30 seconds across 3,000 applications.

This is achieved via pre-built inverted indexes:
- **Package → Application index:** "Which apps use package X?"
- **CPE → Application index:** "Which apps match CPE Y?"
- **Version range index:** Efficient range queries on semantic versions

---

## 5. SLA Management & Escalation

### 5.1 SLA Policy Matrix

| CVE Severity | Tier 1 (Critical Business) | Tier 2 (Important) | Tier 3 (Standard) |
|---|---|---|---|
| **Critical** (CVSS ≥ 9.0) | 24 hours | 48 hours | 7 days |
| **High** (CVSS 7.0–8.9) | 48 hours | 7 days | 14 days |
| **Medium** (CVSS 4.0–6.9) | 7 days | 30 days | 60 days |
| **Low** (CVSS < 4.0) | 30 days | 90 days | 90 days |

### 5.2 SLA Overrides

| Condition | Override |
|---|---|
| CVE is on **CISA KEV** | Use Critical SLA regardless of CVSS |
| **Active exploitation** confirmed (EPSS > 0.9) | Escalate one tier |
| **Public exploit** available (Metasploit, PoC) | Escalate one tier |
| App has **compensating controls** (WAF, network isolation) | Extend SLA by 50% (with approval) |
| **Exception approved** by CISO | Custom deadline per exception |

### 5.3 SLA Clock Rules

- **Clock starts:** The later of (a) CVE publication date, or (b) Sentinel finding creation date
  - Rationale: Can't remediate what you don't know about. But if Sentinel is slow to detect, that's Sentinel's problem, not the app team's.
- **Clock pauses:** Only during approved exception windows
- **Clock stops:** When finding reaches "Verified" status
- **Business hours vs. calendar hours:** Configurable per policy. Default: calendar hours for Critical/High, business hours for Medium/Low.

### 5.4 Escalation Chain

```
SLA Timeline
│
│ 0% ─── Finding created. App owner notified.
│        ServiceNow incident created.
│
│ 50% ── No action taken?
│        → Reminder to app owner (email + Slack/Teams)
│        → Finding flagged yellow on dashboard
│
│ 75% ── Not patched?
│        → Escalate to team lead AND engineering manager
│        → Finding flagged orange on dashboard
│        → Daily standup reminder
│
│ 90% ── Still not resolved?
│        → Escalate to CISO / VP of Engineering
│        → Finding flagged red on dashboard
│        → Auto-upgrade ServiceNow incident priority
│
│ 100% ─ SLA BREACHED
│        → Executive dashboard alert
│        → ServiceNow incident severity upgraded to P1
│        → Added to "overdue" compliance report
│        → Tracked as SLA miss for metrics
│
│ 100%+ ─ Continued breach
│         → Weekly executive report includes breach details
│         → Counted against team's SLA compliance score
```

### 5.5 Exception Workflow

App owners can request SLA exceptions when legitimate business reasons exist:

```
Exception Request:
├── Finding: FIND-2024-00847 (CVE-2024-3094 on PaymentGateway)
├── Requested by: Jane Smith (App Owner)
├── Justification: "Patch requires major framework upgrade. WAF rule
│   deployed as mitigating control. Scheduled for Sprint 14 (2 weeks)."
├── Mitigating controls: WAF rule blocking exploit vector deployed 2024-03-30
├── Requested new deadline: 2024-04-14
├── Risk acceptance: "Residual risk accepted by VP Engineering per policy SEC-012"
│
├── Approval chain:
│   ├── Team Lead: Approved
│   └── CISO: Approved (with condition: WAF logs reviewed daily)
│
└── Status: APPROVED — SLA extended to 2024-04-14
    New escalation chain starts from new deadline
```

All exceptions are logged and auditable. Compliance reports show "SLA met with exception" vs. "SLA met" vs. "SLA breached."

---

## 6. Remediation Workflow

### 6.1 Auto-Triage with Claude

When a new finding is created, Claude analyzes the CVE in context of the affected application:

```
┌─────────────────────────────────────────────────────────┐
│                Claude Auto-Triage                        │
│                                                          │
│ Input:                                                   │
│ ├── CVE details (description, CVSS, affected versions)   │
│ ├── Application context (tech stack, tier, environment)  │
│ ├── CMDB relationships (dependencies, network zone)      │
│ └── Historical data (similar CVEs, past remediation)     │
│                                                          │
│ Output:                                                  │
│ ├── Affected? YES/NO/UNCERTAIN (with reasoning)          │
│ ├── Exploitability assessment in this app's context      │
│ ├── Recommended remediation:                             │
│ │   ├── Primary: "Upgrade spring-core to 5.3.25+"       │
│ │   └── Alternate: "Deploy WAF rule to block X header"  │
│ ├── Estimated effort: "Package bump, low risk, ~1 hour" │
│ ├── Breaking change risk: "Minor API change in 5.3.25,  │
│ │   review release notes section 4.2"                    │
│ └── Persona-specific summaries:                          │
│     ├── For developer: technical details                 │
│     ├── For manager: business impact + timeline          │
│     └── For exec: risk posture in one sentence           │
└─────────────────────────────────────────────────────────┘
```

**Auto-close conditions:**
- CVE is disputed/rejected by NVD → auto-close all findings
- Application confirmed not using affected version → auto-close (HIGH confidence required)
- CVE only affects configuration not in use → auto-close with reasoning

### 6.2 Bulk Operations

A single CVE like Log4Shell can affect hundreds of applications simultaneously. Bulk operations are essential:

```
CVE-2021-44228 (Log4Shell)
├── Correlation: 347 of 3,000 apps affected
│
├── Bulk Triage:
│   ├── Claude auto-triages all 347
│   ├── 298 confirmed affected (HIGH confidence)
│   ├── 38 likely affected (MEDIUM confidence) → quick review queue
│   └── 11 uncertain (LOW confidence) → manual triage queue
│
├── Bulk Assignment:
│   ├── Auto-assign to app owners from CMDB
│   ├── 47 unique teams involved
│   └── Each team gets consolidated view: "Your apps affected: [list]"
│
├── Bulk Patch Tracking:
│   ├── Teams report patches via ServiceNow change records
│   ├── Sentinel tracks per-app progress
│   └── Dashboard: "Log4Shell: 298 affected → 250 patched → 48 remaining"
│
└── Bulk Verification:
    ├── Re-scan via agents where available
    ├── SBOM check for updated dependency
    └── Manual attestation with evidence for remainder
```

### 6.3 Verification Methods

| Method | How It Works | Confidence | Automation |
|---|---|---|---|
| **Agent re-scan** | Agent reports new package version | HIGH | Fully automated |
| **SBOM update** | New SBOM shows patched version | HIGH | Automated via CI/CD |
| **Container image scan** | New image digest without vuln | HIGH | Automated |
| **ServiceNow change record** | Change request closed successfully | MEDIUM | Semi-automated |
| **Manual attestation** | Engineer uploads evidence (screenshot, log) | MEDIUM | Manual |
| **Version API check** | Query app health endpoint for version | HIGH | Automated |

### 6.4 Remediation Paths by App Type

| App Type | Remediation Approach |
|---|---|
| **Homegrown (containerized)** | Update dependency → rebuild image → deploy |
| **Homegrown (VM-based)** | Update package → test → deploy via change window |
| **COTS (vendor-supported)** | Apply vendor patch → test → deploy |
| **COTS (EOL/unsupported)** | Mitigate or plan migration |
| **SaaS** | Verify vendor has patched → monitor vendor advisory (see [Section 8](#8-handling-saas-applications)) |
| **Infrastructure (OS-level)** | OS patching via existing patch management tools |

---

## 7. Reporting & Compliance

### 7.1 Executive Dashboard

```
┌──────────────────────────────────────────────────────────────────────┐
│  SENTINEL ENTERPRISE — Executive Summary            Feb 28, 2026    │
│──────────────────────────────────────────────────────────────────────│
│                                                                      │
│  Open Vulnerabilities          SLA Compliance (30-day rolling)       │
│  ┌─────────────────┐          ┌──────────────────────────────┐      │
│  │ Critical:    12  │          │ ████████████████████░░ 94.2% │      │
│  │ High:        87  │          │ Target: 95%                  │      │
│  │ Medium:     342  │          │ Trend: ▲ +1.3% from last mo │      │
│  │ Low:        891  │          └──────────────────────────────┘      │
│  │ TOTAL:    1,332  │                                                │
│  └─────────────────┘          MTTR (Mean Time to Remediate)          │
│                               ┌──────────────────────────────┐      │
│  Overdue Findings              │ Critical: 18h (target: 24h) ✅│      │
│  ┌─────────────────┐          │ High:     4.2d (target: 7d) ✅│      │
│  │ Critical:     1  │          │ Medium:   22d (target: 30d) ✅│      │
│  │ High:         8  │          │ Low:      45d (target: 90d) ✅│      │
│  │ Medium:      23  │          └──────────────────────────────┘      │
│  │ TOTAL:       32  │                                                │
│  └─────────────────┘          Top 5 Riskiest Applications            │
│                               ┌──────────────────────────────┐      │
│  CISA KEV Active: 3           │ 1. PaymentGateway (12 crit)  │      │
│  Exploited in Wild: 7         │ 2. UserAuthService (8 crit)  │      │
│                               │ 3. DataPipeline (6 crit)     │      │
│                               │ 4. LegacyPortal (5 crit)    │      │
│                               │ 5. APIGateway (4 crit)       │      │
│                               └──────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
```

### 7.2 Team Dashboard

```
┌──────────────────────────────────────────────────────────────────────┐
│  MY TEAM: Platform Engineering               Logged in: Jane Smith  │
│──────────────────────────────────────────────────────────────────────│
│                                                                      │
│  🔴 PATCH TODAY (SLA < 24h remaining)                                │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ CVE-2024-3094  PaymentGateway  xz-utils    SLA: 6h left     │   │
│  │ CVE-2024-1234  UserService     openssl      SLA: 18h left    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  🟡 PATCH THIS WEEK (SLA < 7d remaining)                            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ CVE-2024-5678  PaymentGateway  spring-core  SLA: 3d left    │   │
│  │ CVE-2024-9012  APIGateway      nginx        SLA: 5d left     │   │
│  │ CVE-2024-3456  DataPipeline    postgresql   SLA: 6d left     │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  My Apps: 12 total │ 8 clean │ 4 with open findings                  │
│  My SLA Compliance: 96.1% (30-day rolling)                           │
└──────────────────────────────────────────────────────────────────────┘
```

### 7.3 Compliance Reports

**Audit-ready evidence chain per finding:**

```
Finding: FIND-2024-00847
├── CVE: CVE-2024-3094 (CVSS 10.0, CISA KEV)
├── Application: PaymentGateway (Tier 1)
├── Detection: 2024-03-30T08:15:00Z (within 2h of CVE publication)
├── Triage: 2024-03-30T08:15:30Z (auto-triage by Claude)
├── Assignment: 2024-03-30T08:16:00Z (auto-assigned to Jane Smith)
├── ServiceNow Incident: INC0012345 (P1, created automatically)
├── Remediation started: 2024-03-30T09:00:00Z
├── Patch applied: 2024-03-30T14:00:00Z (xz-utils upgraded to 5.6.2)
├── Verification: 2024-03-30T14:30:00Z (agent re-scan confirmed)
├── ServiceNow Change: CHG0054321 (closed successful)
├── Finding closed: 2024-03-30T14:30:00Z
├── SLA deadline was: 2024-03-31T08:15:00Z (24h)
├── SLA met: YES (6.25 hours, well within 24h SLA)
└── Evidence artifacts:
    ├── Agent scan report (before/after)
    ├── ServiceNow incident timeline
    ├── ServiceNow change record
    └── Git commit: abc123 (dependency update)
```

**Compliance framework mapping:**

| Framework | Control | How Sentinel Provides Evidence |
|---|---|---|
| **SOC 2** | CC7.1 — Vulnerability management | Finding lifecycle with timestamps |
| **ISO 27001** | A.12.6.1 — Technical vulnerability management | SLA compliance reports, remediation evidence |
| **PCI DSS 4.0** | 6.3 — Identify and address vulnerabilities | Quarterly scan reports, patch verification |
| **NIST CSF** | ID.RA-1 — Asset vulnerabilities identified | CVE-to-asset correlation evidence |
| **FedRAMP** | RA-5 — Vulnerability scanning | Continuous monitoring evidence, POA&M generation |

**Report formats:**
- **PDF** — Executive summary, branded, chart-heavy
- **CSV/JSON** — Raw data for import into GRC tools
- **ServiceNow** — Direct push to reporting tables/dashboards
- **SIEM** — CEF/JSON events for Splunk, Sentinel (Azure), etc.

### 7.4 API & Integrations

**Slack/Teams Bot:**
```
User: @sentinel status CVE-2024-3094
Bot:  CVE-2024-3094 (xz-utils backdoor) — CVSS 10.0, CISA KEV
      Affected apps: 3 (PaymentGateway, UserService, ContainerPlatform)
      Status: 2/3 patched, 1 in progress (ContainerPlatform, SLA: 6h remaining)
      Owner: Platform Engineering / Bob Jones

User: @sentinel overdue
Bot:  32 overdue findings:
      🔴 1 Critical (PaymentGateway — CVE-2024-9999, 2h overdue)
      🟠 8 High (see dashboard for details)
      🟡 23 Medium
```

**CI/CD Gate:**
```yaml
# .github/workflows/deploy.yml
- name: Sentinel Security Gate
  run: sentinel gate --app payment-gateway --env production
  # Blocks deployment if:
  # - Any unpatched Critical CVE
  # - Any SLA-breached High CVE
  # - Configurable policy per environment
```

---

## 8. Handling SaaS Applications

~30-40% of enterprise application catalogues are SaaS. You can't patch Salesforce, but you still need to track risk.

### 8.1 SaaS Vulnerability Tracking Model

```
┌─────────────────────────────────────────────────┐
│             SaaS Application Tracking            │
│                                                  │
│  Sentinel monitors:                              │
│  ├── Vendor security advisory pages              │
│  ├── Vendor status pages (statuspage.io, etc.)   │
│  ├── CVE databases for vendor products           │
│  ├── Vendor SOC 2 / compliance updates           │
│  └── Vendor communication channels               │
│                                                  │
│  Findings for SaaS apps:                         │
│  ├── Status: "Vendor Aware" / "Vendor Patched"  │
│  │           / "Awaiting Vendor" / "Our Config"  │
│  ├── Responsibility: Vendor / Shared / Ours      │
│  └── Action: Monitor / Configure / Accept Risk   │
└─────────────────────────────────────────────────┘
```

### 8.2 Shared Responsibility Matrix

| Component | Vendor Responsibility | Your Responsibility |
|---|---|---|
| Platform infrastructure | Patch servers, runtime | Nothing |
| Application code | Fix vulnerabilities | Monitor vendor advisories |
| Configuration | Provide secure defaults | Enforce secure configuration |
| Authentication | Support SSO/MFA | Enable and enforce SSO/MFA |
| Data encryption | Encrypt at rest/transit | Manage encryption keys (if applicable) |
| API security | Secure endpoints | Validate API usage, rotate keys |

### 8.3 SaaS SLA Tracking

SaaS findings have modified SLA semantics:
- **Vendor-owned findings:** SLA = vendor's committed response time + your verification window
- **Configuration-owned findings:** Standard SLA applies (you control the fix)
- **Tracking metric:** "Vendor SLA compliance" — how quickly vendors patch vs. their commitments

---

## 9. Tech Stack for Enterprise

### 9.1 Architecture Decisions

```
┌─────────────────────────────────────────────────────────────────┐
│                    Deployment Architecture                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Kubernetes Cluster                      │    │
│  │                                                          │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │    │
│  │  │ API       │  │ API       │  │ API       │  (3+ pods)  │    │
│  │  │ Server    │  │ Server    │  │ Server    │              │    │
│  │  └────┬──────┘  └─────┬────┘  └────┬──────┘              │    │
│  │       └───────────┬───┘────────────┘                      │    │
│  │                   │                                       │    │
│  │  ┌──────────┐  ┌─▼────────┐  ┌──────────┐              │    │
│  │  │ CVE       │  │ CMDB Sync │  │ SLA       │  Workers    │    │
│  │  │ Ingester  │  │ Worker    │  │ Worker    │              │    │
│  │  └──────────┘  └──────────┘  └──────────┘              │    │
│  │                                                          │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │    │
│  │  │ Correlat- │  │ Notific-  │  │ Report    │  Workers    │    │
│  │  │ ion Engine│  │ ation Svc │  │ Generator │              │    │
│  │  └──────────┘  └──────────┘  └──────────┘              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │PostgreSQL │  │  Redis    │  │Elastic-   │  │ RabbitMQ │       │
│  │ (Primary  │  │ (Cache +  │  │search     │  │ (Task    │       │
│  │  + Read   │  │  Pub/Sub) │  │(Search)   │  │  Queue)  │       │
│  │  Replicas)│  │           │  │           │  │          │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Technology Choices

| Component | Choice | Rationale |
|---|---|---|
| **Language** | Go (API, correlation engine) + Python (Claude integration, analytics) | Go for performance-critical paths, Python for AI/ML and rapid development |
| **API Framework** | Go: Chi/Fiber; Python: FastAPI | High-performance, async-capable |
| **Database** | PostgreSQL 16 | ACID compliance for audit trail, JSONB for flexible metadata, excellent at relational queries |
| **Cache** | Redis 7 | Dashboard real-time updates, session management, rate limiting |
| **Search** | Elasticsearch 8 / OpenSearch | Full-text search across CVEs, apps, findings; aggregation for dashboards |
| **Queue** | RabbitMQ | Reliable task delivery for CVE ingestion, correlation jobs, notification dispatch |
| **Auth** | SAML 2.0 + OIDC | Enterprise SSO (Azure AD, Okta, OneLogin) |
| **Frontend** | React + TypeScript | Dashboard SPA with real-time WebSocket updates |
| **AI/LLM** | Claude API (Anthropic) | Auto-triage, remediation suggestions, persona-based reporting |
| **Deployment** | Kubernetes + Helm | Standard enterprise deployment, horizontal scaling |
| **Observability** | OpenTelemetry → Datadog/Grafana | Metrics, traces, logs for operational visibility |

### 9.3 Scaling Estimates

| Metric | Estimate | Design Consideration |
|---|---|---|
| Applications | 3,000+ | Indexed in Elasticsearch, cached in Redis |
| CVEs (total corpus) | ~250,000 | PostgreSQL + Elasticsearch |
| New CVEs/day | ~70 | Each triggers correlation against 3,000 apps |
| Findings (active) | ~5,000–50,000 | PostgreSQL with proper indexing |
| Findings (historical) | ~500,000+/year | Partitioned tables, archive strategy |
| Correlation jobs/day | ~70 × 3,000 = 210,000 matches | Pre-built indexes, sub-second per CVE |
| API requests/day | ~100,000 | Horizontal scaling, Redis cache |
| ServiceNow API calls/day | ~10,000 | Rate-limited, batched operations |

---

## 10. Implementation Phases

### Phase 1: Foundation (Weeks 1–3)

**Goal:** Connect to CMDB, ingest CVEs, build data model.

- [ ] Design and implement PostgreSQL schema
- [ ] ServiceNow CMDB integration (read-only):
  - Full sync of applications, CIs, relationships
  - Delta sync every 15 minutes
- [ ] CVE ingestion from NVD + CISA KEV
- [ ] Basic API server with auth (API key initially)
- [ ] CLI integration: `sentinel enterprise sync-status`

**Deliverable:** Sentinel has a copy of the CMDB app inventory and a current CVE database.

### Phase 2: Correlation + SLA (Weeks 4–6)

**Goal:** Match CVEs to apps, calculate SLAs.

- [ ] CPE-based correlation engine
- [ ] Package-name correlation (for apps with known dependencies)
- [ ] Confidence scoring
- [ ] SLA policy engine with configurable matrix
- [ ] Finding creation pipeline (CVE + App → Finding with SLA)
- [ ] Basic web dashboard (React): open findings, SLA status
- [ ] Claude auto-triage integration

**Deliverable:** New CVEs automatically correlated to affected apps with SLA deadlines.

### Phase 3: Remediation + ServiceNow (Weeks 7–9)

**Goal:** Full remediation lifecycle with ServiceNow ticket automation.

- [ ] ServiceNow incident auto-creation
- [ ] ServiceNow change request integration
- [ ] Remediation state machine (New → ... → Closed)
- [ ] Escalation engine with notification dispatch
- [ ] Exception request workflow
- [ ] Bulk operations (bulk assign, bulk triage)
- [ ] Slack/Teams notification integration

**Deliverable:** End-to-end workflow from CVE discovery to verified remediation.

### Phase 4: Reporting + Compliance (Weeks 10–12)

**Goal:** Dashboards, reports, and compliance evidence.

- [ ] Executive dashboard with all KPIs
- [ ] Team dashboard with "my apps, my CVEs"
- [ ] PDF/CSV compliance report generation
- [ ] SOC 2 / ISO 27001 / PCI DSS report templates
- [ ] SAML/SSO integration (Azure AD)
- [ ] Elasticsearch deployment for search
- [ ] SaaS application tracking module
- [ ] API documentation (OpenAPI spec)

**Deliverable:** Production-ready platform with compliance reporting.

### Phase 5: Advanced (Ongoing)

- [ ] SBOM ingestion and matching (CycloneDX/SPDX)
- [ ] Agent-based discovery for servers
- [ ] Container image scanning integration
- [ ] CI/CD deployment gates
- [ ] GraphQL API for flexible querying
- [ ] ServiceNow portal widgets
- [ ] Risk scoring model (CVSS × exploitability × exposure × business criticality)
- [ ] Threat intelligence feed integration
- [ ] SBOM generation assistance for apps without them

### Resource Estimate

| Phase | Duration | Team Size | Key Roles |
|---|---|---|---|
| Phase 1 | 3 weeks | 3 engineers | Backend (2), ServiceNow integration (1) |
| Phase 2 | 3 weeks | 4 engineers | Backend (2), Frontend (1), ML/AI (1) |
| Phase 3 | 3 weeks | 4 engineers | Backend (2), ServiceNow (1), Frontend (1) |
| Phase 4 | 3 weeks | 4 engineers | Frontend (2), Backend (1), DevOps (1) |
| Phase 5 | Ongoing | 3-5 engineers | Rotating focus areas |

**Total to MVP (Phase 1–4): 12 weeks, 4-person team.**

---

## 11. What Sentinel CLI Becomes

The existing Sentinel CLI doesn't disappear — it evolves into the developer-facing edge of the platform:

```
┌─────────────────────────────────────────────────────────────┐
│                    Sentinel Ecosystem                        │
│                                                              │
│  ┌───────────────┐         ┌──────────────────────────┐    │
│  │ Sentinel CLI   │         │  Sentinel Enterprise      │    │
│  │ (Developer)    │────────▶│  (Platform)               │    │
│  │                │         │                           │    │
│  │ • Scan my repo │         │ • 3,000 app inventory     │    │
│  │ • Check my app │ reports │ • CMDB integration        │    │
│  │ • Quick triage │ to      │ • SLA enforcement         │    │
│  │ • Local dev    │ ──────▶ │ • Remediation tracking    │    │
│  │   workflow     │         │ • Compliance reporting    │    │
│  └───────────────┘         │ • Executive dashboards    │    │
│                             └──────────────────────────┘    │
│                                                              │
│  New CLI commands:                                           │
│  • sentinel scan --report-to enterprise                      │
│  • sentinel enterprise status --app my-app                   │
│  • sentinel enterprise findings --team platform-eng          │
│  • sentinel enterprise gate --app my-app --env prod          │
└─────────────────────────────────────────────────────────────┘
```

**CLI as agent:** Enterprise can push scan requests to CLI agents running in CI/CD or on servers, collecting fresh data and reporting back. The CLI becomes a distributed sensor network.

---

## 12. Competitive Landscape

### Market Comparison

| Capability | Qualys VMDR | Tenable.io | Rapid7 InsightVM | Wiz | Snyk | **Sentinel Enterprise** |
|---|---|---|---|---|---|---|
| **CVE Detection** | ✅ Scanner-based | ✅ Scanner-based | ✅ Scanner-based | ✅ Agentless cloud | ✅ Code/deps | ✅ Multi-source + CMDB |
| **CMDB-Native** | ⚠️ Separate sync | ⚠️ Separate sync | ⚠️ Separate sync | ❌ Own inventory | ❌ Own inventory | ✅ **CMDB is source of truth** |
| **Intelligent Triage** | ❌ Rule-based | ⚠️ VPR scoring | ❌ Rule-based | ⚠️ Risk-based | ⚠️ Priority scoring | ✅ **Claude-powered analysis** |
| **Persona Output** | ❌ One-size | ❌ One-size | ❌ One-size | ❌ One-size | ❌ One-size | ✅ **Dev/Manager/Exec views** |
| **SLA Engine** | ⚠️ Basic | ⚠️ Basic | ⚠️ Basic | ❌ | ❌ | ✅ **Full SLA lifecycle** |
| **ServiceNow Integration** | ⚠️ Plugin | ⚠️ Plugin | ⚠️ Plugin | ⚠️ Webhook | ⚠️ Webhook | ✅ **Deep bidirectional** |
| **Remediation Guidance** | ❌ Generic | ❌ Generic | ❌ Generic | ⚠️ Basic | ✅ Fix PRs | ✅ **Context-aware AI guidance** |
| **Execution Path Analysis** | ❌ | ❌ | ❌ | ✅ Reachability | ✅ Reachability | ✅ **Claude-analyzed paths** |
| **SaaS App Tracking** | ❌ | ❌ | ❌ | ⚠️ Cloud only | ❌ | ✅ **Full shared responsibility** |
| **Pricing Model** | Per-asset ($$$) | Per-asset ($$$) | Per-asset ($$$) | Per-workload ($$$) | Per-developer ($$) | **TBD — per-app or flat** |

### Sentinel's Differentiators

1. **CMDB-Native Architecture:** Built for enterprises where ServiceNow CMDB is the source of truth. Competitors treat CMDB as an afterthought integration; Sentinel treats it as the foundation.

2. **Claude-Powered Intelligence:** Not just "here are 10,000 findings" but "here's what matters, why, and what to do about it." Dramatically reduces triage burden.

3. **Persona-Based Communication:** The same finding is explained differently to a developer (technical fix), a manager (business impact + timeline), and an executive (risk posture change). No other tool does this.

4. **Execution Path Analysis:** Claude analyzes whether vulnerable code is actually reachable in the application's context, eliminating false positives that plague scanner-based tools.

5. **Full SLA Lifecycle:** Most tools detect and dump. Sentinel tracks the entire lifecycle from detection through verified remediation with SLA enforcement, escalation, and exception management.

6. **SaaS Application Coverage:** Competitors focus on infrastructure you control. Sentinel tracks the full catalogue including SaaS with shared responsibility modeling.

### What Existing Tools Get Right (Learn From Them)

- **Qualys/Tenable:** Proven at scale. Millions of assets. We need that reliability.
- **Wiz:** Agentless cloud scanning. Excellent UX. Set the bar for dashboard quality.
- **Snyk:** Developer-first experience. Fix PRs are powerful. CLI integration done right.

Sentinel Enterprise should have the **scale reliability of Qualys**, the **UX quality of Wiz**, the **developer experience of Snyk**, and the **intelligence of Claude** — all built on the enterprise's existing CMDB foundation.

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **CI** | Configuration Item — any asset tracked in ServiceNow CMDB |
| **CPE** | Common Platform Enumeration — standardized naming for software/hardware |
| **SBOM** | Software Bill of Materials — list of all components in an application |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalogue |
| **EPSS** | Exploit Prediction Scoring System — probability of exploitation |
| **MTTR** | Mean Time to Remediate |
| **Finding** | A specific CVE affecting a specific application |
| **Blast Radius** | The set of applications affected by a single CVE |
| **SLA** | Service Level Agreement — time allowed to remediate a finding |

## Appendix B: Key Metrics & Success Criteria

| Metric | Target | Measurement |
|---|---|---|
| SLA Compliance Rate | ≥ 95% | Findings resolved within SLA / total findings |
| Mean Time to Detect | < 4 hours | CVE publication → Sentinel finding creation |
| Mean Time to Triage | < 1 hour | Finding creation → triage decision |
| Mean Time to Remediate (Critical) | < 24 hours | Finding creation → verified patched |
| Blast Radius Calculation Time | < 30 seconds | New CVE → full affected app list |
| False Positive Rate | < 5% | Findings closed as false positive / total findings |
| CMDB Sync Freshness | < 15 minutes | Time since last successful delta sync |
| Dashboard Availability | 99.9% | Uptime of web dashboard |

---

*This document is a living plan. Update as requirements evolve and implementation learnings accumulate.*
