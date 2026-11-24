"""Snyk Platform-inspired ASPM engine: coverage matrix, criticality risk score, release gate, and portfolio builder."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

CRITICALITY_WEIGHTS: Dict[str, float] = {
    "tier1_prod": 1.5,
    "tier2_internal": 1.0,
    "tier3_demo": 0.5,
}

DEFAULT_ASPM_POLICY: Dict[str, bool] = {
    "block_on_p0": True,
    "block_on_tier1_kev": True,
    "warn_on_p1": True,
}


def normalize_criticality(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in CRITICALITY_WEIGHTS:
        return raw
    return "tier2_internal"


def _collect_active_findings(diagram: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect deduplicated non-suppressed findings for a diagram."""
    cr = diagram.get("coderabbit") if isinstance(diagram.get("coderabbit"), dict) else {}
    raw_items: List[Dict[str, Any]] = []
    if cr:
        raw_items.extend(
            it for it in (list(cr.get("action_items") or []) + list(cr.get("findings") or []))
            if isinstance(it, dict)
        )
    if not raw_items:
        deps = diagram.get("deps") if isinstance(diagram.get("deps"), dict) else {}
        raw_items.extend(it for it in (deps.get("security_advisories") or []) if isinstance(it, dict))
        raw_items.extend(it for it in (deps.get("sast_findings") or []) if isinstance(it, dict))

    seen = set()
    active: List[Dict[str, Any]] = []
    for it in raw_items:
        if it.get("suppressed"):
            continue
        file_short = str(it.get("file") or "").split(" (Target:", 1)[0].strip()
        fp = str(it.get("fingerprint") or "").strip()
        key = f"{fp}|{file_short}" if fp else f"{it.get('title', '')}|{file_short}|{it.get('cve', '')}"
        if key in seen:
            continue
        seen.add(key)
        active.append(it)
    return active


def _infer_tier(item: Dict[str, Any]) -> str:
    tier = str(item.get("priority_tier") or "").upper()
    if tier in ("P0", "P1", "P2", "P3"):
        return tier
    sev = str(item.get("severity") or "").lower()
    cat = str(item.get("category") or "").lower()
    if cat in ("secrets", "malware"):
        return "P0"
    if sev in ("critical", "high") or item.get("in_cisa_kev"):
        return "P1"
    if sev == "medium":
        return "P2"
    return "P3"


def _infer_category(item: Dict[str, Any]) -> str:
    cat = str(item.get("category") or "").lower()
    if cat in ("secrets", "sca", "sast", "cicd", "iac", "license", "malware"):
        return cat
    title = str(item.get("title") or "").lower()
    if "シークレット" in title or "secret" in title:
        return "secrets"
    if item.get("cve") or item.get("pkg"):
        return "sca"
    if "zizmor" in title or ".github/workflows" in str(item.get("file") or ""):
        return "cicd"
    if "terraform" in title or "dockerfile" in title or "iac" in title:
        return "iac"
    return "sast"


def compute_coverage_matrix(diagram: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Evaluate scan coverage across 6 security domains for a repository."""
    deps = diagram.get("deps") if isinstance(diagram.get("deps"), dict) else {}
    src_scan = deps.get("source_scan") if isinstance(deps.get("source_scan"), dict) else {}
    wf_scan = deps.get("workflow_scan") if isinstance(deps.get("workflow_scan"), dict) else {}
    posture = diagram.get("github_posture") if isinstance(diagram.get("github_posture"), dict) else {}
    active = _collect_active_findings(diagram)

    cat_counts: Dict[str, int] = {"secrets": 0, "sca": 0, "sast": 0, "cicd": 0, "iac": 0}
    for it in active:
        c = _infer_category(it)
        if c == "malware":
            cat_counts["sca"] += 1
        elif c in cat_counts:
            cat_counts[c] += 1

    has_any_scan = bool(deps) or bool(diagram.get("coderabbit"))

    def _cell(status: str, count: int = 0) -> Dict[str, Any]:
        return {"status": status, "count": count}

    # 1. Secrets
    gitleaks_status = str(src_scan.get("gitleaks") or "").lower()
    if cat_counts["secrets"] > 0:
        secrets_cell = _cell("issues", cat_counts["secrets"])
    elif gitleaks_status in ("error", "timeout", "unavailable", "missing"):
        secrets_cell = _cell("unscanned", 0)
    elif gitleaks_status in ("complete", "partial") or has_any_scan:
        secrets_cell = _cell("clean", 0)
    else:
        secrets_cell = _cell("unscanned", 0)

    # 2. Dependencies (SCA)
    trivy_status = str(src_scan.get("trivy") or "").lower()
    if cat_counts["sca"] > 0:
        sca_cell = _cell("issues", cat_counts["sca"])
    elif deps.get("packages") or trivy_status in ("complete", "partial"):
        sca_cell = _cell("clean", 0)
    elif trivy_status == "no_files":
        sca_cell = _cell("not_applicable", 0)
    else:
        sca_cell = _cell("unscanned", 0)

    # 3. SAST
    semgrep_status = str(src_scan.get("semgrep") or "").lower()
    ruff_status = str(src_scan.get("ruff") or "").lower()
    if cat_counts["sast"] > 0:
        sast_cell = _cell("issues", cat_counts["sast"])
    elif semgrep_status in ("disabled", "no_files") and ruff_status in ("", "disabled", "no_files"):
        sast_cell = _cell("not_applicable", 0)
    elif semgrep_status in ("error", "timeout", "unavailable", "missing") and ruff_status not in ("complete", "partial"):
        sast_cell = _cell("unscanned", 0)
    elif semgrep_status in ("complete", "partial") or ruff_status in ("complete", "partial"):
        sast_cell = _cell("clean", 0)
    elif has_any_scan and not src_scan:
        sast_cell = _cell("clean", 0)
    else:
        sast_cell = _cell("unscanned", 0)

    # 4. CI/CD (zizmor)
    wf_status = str(wf_scan.get("status") or "").lower()
    zizmor_status = str(wf_scan.get("zizmor") or "").lower()
    if cat_counts["cicd"] > 0:
        cicd_cell = _cell("issues", cat_counts["cicd"])
    elif wf_status == "no_workflows":
        cicd_cell = _cell("not_applicable", 0)
    elif wf_status in ("complete", "partial") or zizmor_status in ("complete", "partial"):
        cicd_cell = _cell("clean", 0)
    else:
        cicd_cell = _cell("unscanned", 0)

    # 5. IaC (Trivy)
    if cat_counts["iac"] > 0:
        iac_cell = _cell("issues", cat_counts["iac"])
    elif trivy_status in ("complete", "partial"):
        iac_cell = _cell("clean", 0)
    elif trivy_status == "no_files":
        iac_cell = _cell("not_applicable", 0)
    else:
        iac_cell = _cell("unscanned", 0)

    # 6. GitHub Posture
    vis = str(posture.get("visibility") or "unknown").upper()
    if vis in ("PUBLIC", "PRIVATE", "INTERNAL"):
        posture_issues = 0
        if posture.get("default_branch_protected") is False:
            posture_issues += 1
        if vis == "PUBLIC" and cat_counts["secrets"] > 0:
            posture_issues += 1
        if posture_issues > 0:
            posture_cell = _cell("issues", posture_issues)
        elif posture.get("default_branch_protected") is None and posture.get("error"):
            posture_cell = _cell("unscanned", 0)
        else:
            posture_cell = _cell("clean", 0)
    else:
        posture_cell = _cell("unscanned", 0)

    return {
        "secrets": secrets_cell,
        "sca": sca_cell,
        "sast": sast_cell,
        "cicd": cicd_cell,
        "iac": iac_cell,
        "posture": posture_cell,
    }


def compute_risk_score(diagram: Dict[str, Any]) -> Dict[str, Any]:
    """Compute a 0-100 Risk Score weighted by Business Criticality, P0-P3, KEV, and visibility."""
    criticality = normalize_criticality(diagram.get("criticality"))
    weight = CRITICALITY_WEIGHTS[criticality]
    active = _collect_active_findings(diagram)

    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "kev": 0, "new": 0}
    for it in active:
        tier = _infer_tier(it)
        counts[tier] += 1
        if it.get("in_cisa_kev") or it.get("is_kev"):
            counts["kev"] += 1
        if it.get("is_new"):
            counts["new"] += 1

    raw_points = (
        counts["P0"] * 30
        + counts["P1"] * 12
        + counts["P2"] * 4
        + counts["P3"] * 1
        + counts["kev"] * 15
    )
    weighted = raw_points * weight

    posture = diagram.get("github_posture") if isinstance(diagram.get("github_posture"), dict) else {}
    visibility = str(posture.get("visibility") or "unknown").upper()
    if visibility == "PUBLIC" and (counts["P0"] > 0 or counts["P1"] > 0):
        weighted += 15

    score = min(100, max(0, int(round(weighted))))
    return {
        "risk_score": score,
        "criticality": criticality,
        "weight": weight,
        "counts": counts,
    }


def evaluate_release_gate(
    diagram: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate PASS / WARN / BLOCK release guardrail for a repository."""
    pol = {**DEFAULT_ASPM_POLICY, **(policy or {})}
    risk = compute_risk_score(diagram)
    counts = risk["counts"]
    criticality = risk["criticality"]

    block_reasons: List[str] = []
    warn_reasons: List[str] = []

    if pol.get("block_on_p0", True) and counts["P0"] > 0:
        block_reasons.append(f"未解決の P0（実シークレット/マルウェア等）が {counts['P0']} 件あります")
    if pol.get("block_on_tier1_kev", True) and criticality == "tier1_prod" and counts["kev"] > 0:
        block_reasons.append(f"Tier 1 本番資産に CISA KEV 該当 CVE が {counts['kev']} 件あります")

    if pol.get("warn_on_p1", True) and counts["P1"] > 0:
        warn_reasons.append(f"高リスク P1 指摘が {counts['P1']} 件残っています")

    if block_reasons:
        gate = "BLOCK"
        reasons = block_reasons + warn_reasons
    elif warn_reasons:
        gate = "WARN"
        reasons = warn_reasons
    else:
        gate = "PASS"
        reasons = ["P0 / P1 の未対応指摘はありません"]

    return {
        "gate": gate,
        "reasons": reasons,
        "counts": counts,
    }


def build_aspm_portfolio(
    diagrams: List[Dict[str, Any]],
    *,
    policy: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build organization-wide ASPM portfolio sorted by risk_score descending."""
    pol = {**DEFAULT_ASPM_POLICY, **(policy or {})}
    repos: List[Dict[str, Any]] = []
    for d in diagrams:
        if not isinstance(d, dict) or d.get("is_root"):
            continue
        risk = compute_risk_score(d)
        gate_info = evaluate_release_gate(d, pol)
        coverage = compute_coverage_matrix(d)
        repos.append(
            {
                "id": str(d.get("id") or ""),
                "repo": str(d.get("repo") or d.get("github_url") or "Repository"),
                "criticality": risk["criticality"],
                "weight": risk["weight"],
                "risk_score": risk["risk_score"],
                "counts": risk["counts"],
                "release_gate": gate_info["gate"],
                "gate_reasons": gate_info["reasons"],
                "coverage": coverage,
            }
        )

    tier_rank = {"tier1_prod": 3, "tier2_internal": 2, "tier3_demo": 1}
    repos.sort(key=lambda r: (r["risk_score"], tier_rank.get(r["criticality"], 0)), reverse=True)

    return {
        "repos": repos,
        "policy": pol,
        "history": list(history or [])[-90:],
    }
