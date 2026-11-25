"""Live Threat Intelligence Feed (CISA KEV + JVN iPedia Critical) correlated with local repository code & configs."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_FALLBACK_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
GHSA_CRITICAL_URL = "https://api.github.com/advisories?severity=critical&per_page=30"
CACHE_TTL_SECONDS = 6 * 3600

# Canonical stack key -> keywords to match in threat titles/products/vendors
STACK_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "php": ("php", "php-fpm", "php-cgi", "laravel", "symfony", "wordpress"),
    "nginx": ("nginx", "ingress-nginx", "openresty"),
    "apache": ("apache http", "httpd", "apache tomcat", "tomcat"),
    "nextjs": ("next.js", "nextjs"),
    "nodejs": ("node.js", "nodejs"),
    "react": ("react", "react-server-dom"),
    "nestjs": ("nestjs", "@nestjs"),
    "express": ("express.js", "expressjs"),
    "python": ("python", "django", "flask", "fastapi"),
    "golang": ("golang", "go standard library"),
    "postgresql": ("postgresql", "postgres"),
    "mysql": ("mysql", "mariadb"),
    "redis": ("redis", "valkey"),
    "openssl": ("openssl",),
    "openssh": ("openssh",),
    "docker": ("docker", "containerd", "runc", "moby"),
    "kubernetes": ("kubernetes", "kubectl", "kubelet", "ingress-nginx"),
    "terraform": ("terraform", "hashicorp"),
    "git": ("git-scm", "github actions", "gitlab"),
    "axios": ("axios",),
    "ckeditor": ("ckeditor",),
}

_DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s@]+)", re.IGNORECASE)
_IMAGE_STACK_MAP: Tuple[Tuple[str, str], ...] = (
    ("nginx", "nginx"),
    ("openresty", "nginx"),
    ("php", "php"),
    ("httpd", "apache"),
    ("tomcat", "apache"),
    ("node", "nodejs"),
    ("python", "python"),
    ("golang", "golang"),
    ("postgres", "postgresql"),
    ("mysql", "mysql"),
    ("mariadb", "mysql"),
    ("redis", "redis"),
    ("valkey", "redis"),
)
_IGNORE_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".next", ".venv", "venv"}


def _cache_path() -> Path:
    override = os.environ.get("REPOAUDT_THREAT_FEED_CACHE", "").strip()
    if override:
        return Path(override)
    return Path(tempfile.gettempdir()) / "repoaudt_threat_feed_cache.json"


def _http_get_text(url: str, timeout: int = 12) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "RepoAUDT-Mac/1.2 (+https://github.com/nanonigit/RepoAUDT-Mac)",
            "Accept": "application/json, application/xml, text/xml, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_cisa_kev_payload(raw_json: str, *, days: int = 120, limit: int = 45) -> List[Dict[str, Any]]:
    """Parse CISA KEV JSON and return recent actively exploited vulnerabilities."""
    data = json.loads(raw_json or "{}")
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else []
    if not isinstance(vulns, list):
        return []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    items: List[Dict[str, Any]] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        date_added = str(v.get("dateAdded") or "").strip()
        if date_added and date_added < cutoff:
            continue
        vendor = str(v.get("vendorProject") or "").strip()
        product = str(v.get("product") or "").strip()
        name = str(v.get("vulnerabilityName") or "").strip()
        desc = str(v.get("shortDescription") or "").strip()
        items.append({
            "cve": cve,
            "source": "CISA KEV",
            "severity": "CRITICAL",
            "product": f"{vendor} {product}".strip() or product or vendor,
            "title": name or f"{vendor} {product} Actively Exploited Vulnerability",
            "summary": desc[:260],
            "published": date_added,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "actively_exploited": True,
        })
    items.sort(key=lambda x: x.get("published") or "", reverse=True)
    return items[:limit]


def parse_ghsa_critical_payload(raw_json: str, *, limit: int = 30) -> List[Dict[str, Any]]:
    """Parse GitHub Security Advisories API JSON for Critical (CVSS 9.0+) vulnerabilities."""
    data = json.loads(raw_json or "[]")
    if not isinstance(data, list):
        return []
    items: List[Dict[str, Any]] = []
    for adv in data:
        if not isinstance(adv, dict):
            continue
        cve = str(adv.get("cve_id") or adv.get("ghsa_id") or "").strip().upper()
        summary = str(adv.get("summary") or "").strip()
        if not summary and not cve:
            continue
        desc = str(adv.get("description") or "").strip()
        published = str(adv.get("published_at") or "")[:10]
        url = str(adv.get("html_url") or (f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else "https://github.com/advisories"))
        pkgs: List[str] = []
        for v in adv.get("vulnerabilities") or []:
            if isinstance(v, dict):
                pname = str((v.get("package") or {}).get("name") or "").strip()
                if pname and pname not in pkgs:
                    pkgs.append(pname)
        product = ", ".join(pkgs[:2]) if pkgs else summary[:48]
        cvss_obj = adv.get("cvss") if isinstance(adv.get("cvss"), dict) else {}
        cvss_score = str(cvss_obj.get("score") or "")
        items.append({
            "cve": cve,
            "source": "GHSA Critical",
            "severity": "CRITICAL",
            "cvss": cvss_score,
            "product": product,
            "title": summary or cve,
            "summary": desc[:260],
            "published": published,
            "url": url,
            "actively_exploited": False,
        })
    items.sort(key=lambda x: x.get("published") or "", reverse=True)
    return items[:limit]


def _detect_stacks_for_threat(item: Dict[str, Any]) -> Set[str]:
    """Match stack keywords strictly against product/vendor (never free-text prose).

    Prevents unrelated packages (e.g. 'ruflo' mentioning 'Docker Compose' in its
    description) from falsely matching repositories that merely contain a Dockerfile.
    """
    product_hay = f"{item.get('product', '')} {item.get('vendor', '')}".strip().lower()
    if not product_hay:
        product_hay = str(item.get("title") or "").lower()
    matched: Set[str] = set()
    for stack, keywords in STACK_KEYWORDS.items():
        for kw in keywords:
            if len(kw) <= 3:
                if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", product_hay):
                    matched.add(stack)
                    break
            elif kw in product_hay:
                matched.add(stack)
                break
    return matched


def extract_repo_inventory(diagram: Dict[str, Any]) -> Tuple[Dict[str, List[str]], Set[str]]:
    """Extract technology stacks (with file evidence) and known CVEs for a repository diagram."""
    stacks: Dict[str, List[str]] = {}
    known_cves: Set[str] = set()

    def _add(stack: str, evidence: str) -> None:
        ev_list = stacks.setdefault(stack, [])
        if evidence not in ev_list and len(ev_list) < 3:
            ev_list.append(evidence)

    deps = diagram.get("deps") if isinstance(diagram.get("deps"), dict) else {}
    for pkg in deps.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "").strip().lower()
        ver = str(pkg.get("version") or "").strip()
        if name == "next":
            _add("nextjs", f"package.json (next {ver})".strip())
        elif name in ("react", "react-dom"):
            _add("react", f"package.json ({name} {ver})".strip())
        elif name.startswith("@nestjs/"):
            _add("nestjs", f"package.json ({name} {ver})".strip())
        elif name == "express":
            _add("express", f"package.json (express {ver})".strip())
        elif name == "axios":
            _add("axios", f"package.json (axios {ver})".strip())
        elif "ckeditor" in name:
            _add("ckeditor", f"package.json ({name} {ver})".strip())
        elif name in ("pg", "knex", "prisma", "@prisma/client"):
            _add("postgresql", f"package.json ({name})")
        elif name in ("mysql", "mysql2"):
            _add("mysql", f"package.json ({name})")
        elif name in ("redis", "ioredis", "bullmq"):
            _add("redis", f"package.json ({name})")

    for db in deps.get("databases") or []:
        if not isinstance(db, dict):
            continue
        dname = str(db.get("name") or "").lower()
        dver = str(db.get("version") or "").strip()
        if "postgres" in dname:
            _add("postgresql", f"DB ({dname} {dver})".strip())
        elif "mysql" in dname or "mariadb" in dname:
            _add("mysql", f"DB ({dname} {dver})".strip())
        elif "redis" in dname:
            _add("redis", f"DB ({dname} {dver})".strip())

    runtime = deps.get("runtime") if isinstance(deps.get("runtime"), dict) else {}
    for rk, rv in runtime.items():
        rkl = str(rk).lower()
        if "node" in rkl:
            _add("nodejs", f"runtime ({rk}: {rv})")
        elif "python" in rkl:
            _add("python", f"runtime ({rk}: {rv})")
        elif "php" in rkl:
            _add("php", f"runtime ({rk}: {rv})")
        elif rkl == "go" or "golang" in rkl:
            _add("golang", f"runtime ({rk}: {rv})")

    for adv in deps.get("security_advisories") or []:
        if isinstance(adv, dict):
            for c in re.findall(r"CVE-\d{4}-\d{4,7}", str(adv.get("cve") or "") + " " + str(adv.get("title") or ""), re.I):
                known_cves.add(c.upper())
    cr = diagram.get("coderabbit") if isinstance(diagram.get("coderabbit"), dict) else {}
    for it in list(cr.get("action_items") or []) + list(cr.get("findings") or []):
        if isinstance(it, dict) and not it.get("suppressed"):
            for c in re.findall(r"CVE-\d{4}-\d{4,7}", str(it.get("cve") or "") + " " + str(it.get("title") or ""), re.I):
                known_cves.add(c.upper())

    # Inspect real files on disk if cached locally (Dockerfile, nginx.conf, composer.json, *.tf, k8s ingress)
    local_raw = str(
        diagram.get("local_path")
        or (diagram.get("source_revision") or {}).get("local_path")
        or ""
    ).strip()
    if not local_raw:
        repo_slug = str(diagram.get("repo") or "").strip()
        if "/" in repo_slug:
            owner, rname = repo_slug.split("/", 1)
            for cand in (
                Path.home() / "Git" / owner / rname,
                Path.home() / "Library/Application Support/RepoAUDT Mac/repos" / f"{owner}__{rname}",
            ):
                if cand.exists():
                    local_raw = str(cand)
                    break

    if local_raw and Path(local_raw).is_dir():
        root_dir = Path(local_raw)
        file_budget = 0
        for root, dirs, filenames in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
            for fn in filenames:
                file_budget += 1
                if file_budget > 1500:
                    break
                low = fn.lower()
                full = Path(root, fn)
                rel = str(full.relative_to(root_dir))
                if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
                    _add("docker", rel)
                    try:
                        for idx, ln in enumerate(full.read_text(encoding="utf-8", errors="ignore").splitlines()[:80], 1):
                            m = _DOCKER_FROM_RE.match(ln)
                            if not m:
                                continue
                            img = m.group(1).strip()
                            img_low = img.lower()
                            for token, st_key in _IMAGE_STACK_MAP:
                                if token in img_low:
                                    _add(st_key, f"{rel}:{idx} (FROM {img})")
                    except OSError:
                        pass
                elif low == "nginx.conf" or (low.endswith(".conf") and "nginx" in rel.lower()):
                    _add("nginx", rel)
                elif low == "composer.json" or low.endswith(".php"):
                    _add("php", rel)
                elif low.endswith(".tf"):
                    _add("terraform", rel)
                elif low.startswith("next.config."):
                    _add("nextjs", rel)
                elif low == "package.json":
                    _add("nodejs", rel)
                elif low in ("requirements.txt", "pyproject.toml"):
                    _add("python", rel)
                elif low == "go.mod":
                    _add("golang", rel)
                elif low.endswith((".yaml", ".yml")) and ("k8s" in rel.lower() or "kube" in rel.lower() or "ingress" in low):
                    try:
                        txt = full.read_text(encoding="utf-8", errors="ignore")[:8192]
                        if "kind: Ingress" in txt or "ingress.kubernetes.io" in txt:
                            _add("kubernetes", rel)
                            if "nginx" in txt.lower():
                                _add("nginx", f"{rel} (Ingress-NGINX)")
                    except OSError:
                        pass
            if file_budget > 1500:
                break

    return stacks, known_cves


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _build_global_finding_index(non_root: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Compute per-tier index codes (P0-01, P1-01, ...) matching WorkspaceView.openDrilldown."""
    tier_rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    collected: List[Tuple[Any, Dict[str, Any]]] = []

    for d in non_root:
        did = str(d.get("id") or "").strip()
        repo_name = str(d.get("repo") or d.get("github_url") or "Repository").strip()
        cr = d.get("coderabbit") if isinstance(d.get("coderabbit"), dict) else {}
        seen: Set[str] = set()
        for it in (cr.get("action_items") or []):
            if not isinstance(it, dict) or it.get("suppressed"):
                continue
            tier = str(it.get("priority_tier") or "P2").upper()
            title = str(it.get("title") or "")
            file_str = str(it.get("file") or "").split(" (Target:", 1)[0]
            key = f"{did}|{title}|{file_str}"
            if key in seen:
                continue
            seen.add(key)
            k_rank = 0 if it.get("in_cisa_kev") else 1
            c_rank = conf_rank.get(str(it.get("confidence") or "medium").lower(), 2)
            s_rank = sev_rank.get(str(it.get("severity") or "medium").lower(), 3)
            try:
                epss_val = float(it.get("epss_score") or 0.0)
            except (TypeError, ValueError):
                epss_val = 0.0
            sort_key = (
                tier_rank.get(tier, 3),
                k_rank,
                c_rank,
                s_rank,
                -epss_val,
                f"{repo_name}|{file_str}|{title}",
            )
            blob = " ".join([title, str(it.get("desc") or ""), str(it.get("cve") or ""), file_str]).upper()
            collected.append((sort_key, {
                "diagram_id": did,
                "repo": repo_name,
                "tier": tier,
                "title": title,
                "file": file_str,
                "fingerprint": str(it.get("fingerprint") or ""),
                "cves": set(_CVE_RE.findall(blob)),
            }))

    collected.sort(key=lambda x: x[0])
    counters: Dict[str, int] = {}
    by_repo: Dict[str, List[Dict[str, Any]]] = {}
    for _, entry in collected:
        t = entry["tier"]
        counters[t] = counters.get(t, 0) + 1
        entry["index_code"] = f"{t}-{counters[t]:02d}"
        by_repo.setdefault(entry["repo"], []).append(entry)
    return by_repo


def fetch_and_correlate_threat_feed(
    diagrams: List[Dict[str, Any]],
    *,
    force: bool = False,
    fetcher: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """Fetch CISA KEV + JVN Critical feeds (6h TTL cached) and correlate with saved repositories."""
    now_ts = time.time()
    cache_file = _cache_path()
    feed_items: List[Dict[str, Any]] = []
    sources_meta: Dict[str, Any] = {
        "cisa_kev": {"ok": False, "count": 0},
        "ghsa_critical": {"ok": False, "count": 0},
    }
    fetched_at = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    used_cache = False

    if not force and fetcher is None and cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and now_ts - float(cached.get("ts", 0)) < CACHE_TTL_SECONDS:
                feed_items = list(cached.get("items") or [])
                sources_meta = dict(cached.get("sources") or sources_meta)
                fetched_at = str(cached.get("fetched_at") or fetched_at)
                used_cache = True
        except Exception:
            used_cache = False

    if not used_cache:
        get_fn = fetcher or _http_get_text
        raw_combined: List[Dict[str, Any]] = []
        try:
            kev_raw = get_fn(CISA_KEV_URL)
            kev_items = parse_cisa_kev_payload(kev_raw)
            raw_combined.extend(kev_items)
            sources_meta["cisa_kev"] = {"ok": True, "count": len(kev_items)}
        except Exception as primary_exc:
            try:
                kev_raw = get_fn(CISA_KEV_FALLBACK_URL)
                kev_items = parse_cisa_kev_payload(kev_raw)
                raw_combined.extend(kev_items)
                sources_meta["cisa_kev"] = {"ok": True, "count": len(kev_items), "mirror": "github"}
            except Exception as fallback_exc:
                sources_meta["cisa_kev"] = {
                    "ok": False,
                    "count": 0,
                    "error": f"{str(primary_exc)[:80]} / mirror: {str(fallback_exc)[:80]}",
                }

        try:
            ghsa_raw = get_fn(GHSA_CRITICAL_URL)
            ghsa_items = parse_ghsa_critical_payload(ghsa_raw)
            raw_combined.extend(ghsa_items)
            sources_meta["ghsa_critical"] = {"ok": True, "count": len(ghsa_items)}
        except Exception as exc:
            sources_meta["ghsa_critical"] = {"ok": False, "count": 0, "error": str(exc)[:120]}

        # Deduplicate by CVE (prefer CISA KEV when same CVE appears in both)
        seen_cves: Set[str] = set()
        for it in raw_combined:
            cve = str(it.get("cve") or "").upper()
            dedup_key = cve or f"title:{it.get('title', '')[:60]}"
            if dedup_key in seen_cves:
                continue
            seen_cves.add(dedup_key)
            feed_items.append(it)

        if fetcher is None and feed_items:
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(
                    json.dumps(
                        {"ts": now_ts, "fetched_at": fetched_at, "sources": sources_meta, "items": feed_items},
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
            except OSError:
                pass

    # Build repository inventories & global P0/P1/P2/P3 finding index
    non_root = [d for d in diagrams if isinstance(d, dict) and not d.get("is_root")]
    findings_by_repo = _build_global_finding_index(non_root)
    repo_inventories: List[Tuple[str, str, Dict[str, List[str]], Set[str]]] = []
    stack_repo_counts: Dict[str, int] = {}
    for d in non_root:
        did = str(d.get("id") or "").strip()
        rname = str(d.get("repo") or d.get("github_url") or "Repository").strip()
        st_map, cve_set = extract_repo_inventory(d)
        repo_inventories.append((did, rname, st_map, cve_set))
        for sk in st_map:
            stack_repo_counts[sk] = stack_repo_counts.get(sk, 0) + 1

    # Correlate each threat item against repository inventories
    correlated: List[Dict[str, Any]] = []
    matched_count = 0
    for it in feed_items:
        cve = str(it.get("cve") or "").upper()
        threat_stacks = _detect_stacks_for_threat(it)
        matched_repos: List[Dict[str, Any]] = []
        has_confirmed = False

        for did, rname, st_map, cve_set in repo_inventories:
            confirmed = bool(cve and cve in cve_set)
            evidences: List[str] = []
            for sk in sorted(threat_stacks):
                if sk in st_map:
                    evidences.extend(st_map[sk])
            if confirmed or evidences:
                if confirmed:
                    has_confirmed = True
                finding_refs: List[Dict[str, str]] = []
                if confirmed and cve:
                    for f_entry in findings_by_repo.get(rname, []):
                        if cve in f_entry.get("cves", set()):
                            finding_refs.append({
                                "index_code": f_entry["index_code"],
                                "tier": f_entry["tier"],
                                "fingerprint": f_entry["fingerprint"],
                                "title": f_entry["title"],
                                "file": f_entry["file"],
                            })
                matched_repos.append({
                    "diagram_id": did,
                    "repo": rname,
                    "confirmed_cve": confirmed,
                    "evidence": " · ".join(evidences[:2]) if evidences else ("Detected in repo advisories" if confirmed else ""),
                    "finding_refs": finding_refs[:5],
                })

        if has_confirmed:
            match_status = "confirmed"
            matched_count += 1
        elif matched_repos:
            match_status = "stack_match"
            matched_count += 1
        else:
            match_status = "not_affected"

        correlated.append({
            **it,
            "detected_stacks": sorted(threat_stacks),
            "match_status": match_status,
            "matched_repos": matched_repos,
        })

    # Sort: confirmed first, then stack_match, then not_affected (each newest first)
    status_rank = {"confirmed": 0, "stack_match": 1, "not_affected": 2}
    correlated.sort(key=lambda x: (status_rank.get(x["match_status"], 3), -(int(re.sub(r"\D", "", str(x.get("published") or "0")) or "0"))))

    return {
        "ok": True,
        "fetched_at": fetched_at,
        "cached": used_cache,
        "sources": sources_meta,
        "scanned_repos": len(non_root),
        "stack_inventory": dict(sorted(stack_repo_counts.items(), key=lambda kv: -kv[1])),
        "matched_count": matched_count,
        "unaffected_count": len(correlated) - matched_count,
        "items": correlated,
    }
