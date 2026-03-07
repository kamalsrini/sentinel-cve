"""SSVC 2.1 Decision Tree — Stakeholder-Specific Vulnerability Categorization.

Implements CERT/CC SSVC v2.1 decision tree for vulnerability prioritization.
Produces action-oriented decisions (Defer/Scheduled/Out-of-Cycle/Immediate)
instead of numeric scores.

Reference: https://certcc.github.io/SSVC/
"""

from __future__ import annotations

from typing import Any


# ── Decision point values ─────────────────────────────────────────────────

class Exploitation:
    NONE = "none"
    POC = "poc"
    ACTIVE = "active"


class Automatable:
    NO = "no"
    YES = "yes"


class TechnicalImpact:
    PARTIAL = "partial"
    TOTAL = "total"


class MissionPrevalence:
    MINIMAL = "minimal"
    SUPPORT = "support"
    ESSENTIAL = "essential"


# ── Decision outcomes ─────────────────────────────────────────────────────

class Decision:
    DEFER = "Defer"
    SCHEDULED = "Scheduled"
    OUT_OF_CYCLE = "Out-of-Cycle"
    IMMEDIATE = "Immediate"


# ── SLA mapping ───────────────────────────────────────────────────────────

SLA_MAP: dict[str, dict[str, str | int]] = {
    Decision.IMMEDIATE: {"timeframe": "24 hours", "hours": 24},
    Decision.OUT_OF_CYCLE: {"timeframe": "72 hours", "hours": 72},
    Decision.SCHEDULED: {"timeframe": "30 days", "hours": 720},
    Decision.DEFER: {"timeframe": "90 days", "hours": 2160},
}


def evaluate_ssvc(
    cvss_metrics: dict[str, Any] | None = None,
    kev_listed: bool = False,
    kev_ransomware: bool = False,
    epss_score: float | None = None,
    deployment_context: str = "support",
) -> dict[str, Any]:
    """Evaluate a vulnerability using the SSVC 2.1 decision tree.

    Args:
        cvss_metrics: CVSS metric dict with keys like attackVector,
            attackComplexity, privilegesRequired, userInteraction, baseScore, etc.
        kev_listed: Whether the CVE is on the CISA KEV catalog.
        kev_ransomware: Whether KEV indicates known ransomware use.
        epss_score: EPSS probability (0.0-1.0).
        deployment_context: One of 'minimal', 'support', 'essential'.

    Returns:
        Dict with exploitation, automatable, technical_impact, mission_prevalence,
        decision, sla, and rationale.
    """
    if cvss_metrics is None:
        cvss_metrics = {}

    exploitation = _assess_exploitation(kev_listed, epss_score, cvss_metrics)
    automatable = _assess_automatable(cvss_metrics)
    technical_impact = _assess_technical_impact(cvss_metrics)
    mission_prevalence = _normalize_mission(deployment_context)
    decision = _decide(exploitation, automatable, technical_impact, mission_prevalence)

    # Escalation overrides
    if kev_ransomware:
        decision = Decision.IMMEDIATE

    sla = SLA_MAP[decision]

    rationale = _build_rationale(
        exploitation, automatable, technical_impact, mission_prevalence, decision,
        kev_listed, kev_ransomware, epss_score,
    )

    return {
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "mission_prevalence": mission_prevalence,
        "decision": decision,
        "sla_tier": sla["timeframe"],
        "sla_hours": sla["hours"],
        "rationale": rationale,
    }


def _assess_exploitation(
    kev_listed: bool,
    epss_score: float | None,
    cvss_metrics: dict[str, Any],
) -> str:
    """Determine exploitation status."""
    # KEV listing = confirmed active exploitation
    if kev_listed:
        return Exploitation.ACTIVE

    # High EPSS indicates likely active exploitation
    if epss_score is not None and epss_score > 0.5:
        return Exploitation.ACTIVE

    # Moderate EPSS suggests PoC-level exploitation
    if epss_score is not None and epss_score > 0.1:
        return Exploitation.POC

    # Check exploit maturity from CVSS threat metrics if available
    exploit_maturity = cvss_metrics.get("exploitMaturity", "").upper()
    if exploit_maturity in ("ATTACKED", "A"):
        return Exploitation.ACTIVE
    if exploit_maturity in ("POC", "P"):
        return Exploitation.POC

    return Exploitation.NONE


def _assess_automatable(cvss_metrics: dict[str, Any]) -> str:
    """Determine if exploitation can be automated (wormable/scriptable)."""
    av = cvss_metrics.get("attackVector", "").upper()
    ac = cvss_metrics.get("attackComplexity", "").upper()
    pr = cvss_metrics.get("privilegesRequired", "").upper()
    ui = cvss_metrics.get("userInteraction", "").upper()

    # Automatable: network-accessible, no auth, no user interaction, low complexity
    if av == "NETWORK" and pr == "NONE" and ac == "LOW":
        if ui in ("NONE", "N"):
            return Automatable.YES

    return Automatable.NO


def _assess_technical_impact(cvss_metrics: dict[str, Any]) -> str:
    """Determine technical impact (partial vs total)."""
    base_score = cvss_metrics.get("baseScore", 0)

    # Check for total impact indicators
    # CVSS 4.0 uses VC/VI/VA for vulnerable system
    vc = cvss_metrics.get("confidentialityImpact", cvss_metrics.get("VC", "")).upper()
    vi = cvss_metrics.get("integrityImpact", cvss_metrics.get("VI", "")).upper()
    va = cvss_metrics.get("availabilityImpact", cvss_metrics.get("VA", "")).upper()

    # If any CIA metric is HIGH and score >= 9.0, total impact
    if base_score >= 9.0:
        return TechnicalImpact.TOTAL

    # If all three CIA are HIGH, total impact regardless of score
    if vc == "HIGH" and vi == "HIGH" and va == "HIGH":
        return TechnicalImpact.TOTAL

    # RCE-type vulnerabilities (high integrity + high confidentiality) = total
    if vc == "HIGH" and vi == "HIGH":
        return TechnicalImpact.TOTAL

    return TechnicalImpact.PARTIAL


def _normalize_mission(context: str) -> str:
    """Normalize deployment context to SSVC mission prevalence."""
    context = context.lower().strip()
    if context in ("essential", "critical", "revenue", "customer-facing"):
        return MissionPrevalence.ESSENTIAL
    if context in ("support", "internal", "ci-cd", "monitoring"):
        return MissionPrevalence.SUPPORT
    if context in ("minimal", "dev", "test", "development", "non-production"):
        return MissionPrevalence.MINIMAL
    # Default to support (conservative middle ground)
    return MissionPrevalence.SUPPORT


def _decide(
    exploitation: str,
    automatable: str,
    technical_impact: str,
    mission_prevalence: str,
) -> str:
    """Apply SSVC 2.1 decision tree logic."""
    # Immediate: active exploitation + automatable + total impact + essential/support
    if exploitation == Exploitation.ACTIVE:
        if automatable == Automatable.YES:
            if technical_impact == TechnicalImpact.TOTAL:
                return Decision.IMMEDIATE
            # Active + automatable + partial impact + essential
            if mission_prevalence == MissionPrevalence.ESSENTIAL:
                return Decision.IMMEDIATE
            return Decision.OUT_OF_CYCLE
        # Active + not automatable
        if technical_impact == TechnicalImpact.TOTAL:
            if mission_prevalence in (MissionPrevalence.ESSENTIAL, MissionPrevalence.SUPPORT):
                return Decision.IMMEDIATE
            return Decision.OUT_OF_CYCLE
        # Active + not automatable + partial
        if mission_prevalence == MissionPrevalence.ESSENTIAL:
            return Decision.OUT_OF_CYCLE
        return Decision.OUT_OF_CYCLE

    # PoC exploitation
    if exploitation == Exploitation.POC:
        if automatable == Automatable.YES:
            if technical_impact == TechnicalImpact.TOTAL:
                return Decision.OUT_OF_CYCLE
            if mission_prevalence == MissionPrevalence.ESSENTIAL:
                return Decision.OUT_OF_CYCLE
            return Decision.SCHEDULED
        # PoC + not automatable
        if technical_impact == TechnicalImpact.TOTAL:
            if mission_prevalence == MissionPrevalence.ESSENTIAL:
                return Decision.OUT_OF_CYCLE
            return Decision.SCHEDULED
        return Decision.SCHEDULED

    # No exploitation
    if automatable == Automatable.YES and technical_impact == TechnicalImpact.TOTAL:
        if mission_prevalence == MissionPrevalence.ESSENTIAL:
            return Decision.OUT_OF_CYCLE
        return Decision.SCHEDULED

    if technical_impact == TechnicalImpact.TOTAL:
        if mission_prevalence == MissionPrevalence.ESSENTIAL:
            return Decision.SCHEDULED
        return Decision.SCHEDULED

    if mission_prevalence == MissionPrevalence.ESSENTIAL:
        return Decision.SCHEDULED

    return Decision.DEFER


def _build_rationale(
    exploitation: str,
    automatable: str,
    technical_impact: str,
    mission_prevalence: str,
    decision: str,
    kev_listed: bool,
    kev_ransomware: bool,
    epss_score: float | None,
) -> str:
    """Build a human-readable rationale for the SSVC decision."""
    parts = []

    if kev_ransomware:
        parts.append("CISA KEV indicates known ransomware use — escalated to Immediate.")
    elif kev_listed:
        parts.append("Listed on CISA KEV (confirmed active exploitation).")

    if epss_score is not None:
        if epss_score > 0.5:
            parts.append(f"EPSS score {epss_score:.4f} indicates very high exploitation probability.")
        elif epss_score > 0.1:
            parts.append(f"EPSS score {epss_score:.4f} indicates elevated exploitation probability.")

    parts.append(
        f"SSVC path: Exploitation={exploitation}, Automatable={automatable}, "
        f"Technical Impact={technical_impact}, Mission Prevalence={mission_prevalence} "
        f"→ {decision}."
    )

    return " ".join(parts)
