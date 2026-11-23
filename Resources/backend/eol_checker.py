"""Real-time runtime EOL checker backed by endoflife.date with TTL cache and static fallback."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ENDOFLIFE_API_TEMPLATE = "https://endoflife.date/api/{product}.json"
CACHE_TTL_SECONDS = 24 * 3600
DEFAULT_TIMEOUT_SECONDS = 2.5

PRODUCT_ALIASES: Dict[str, str] = {
    "python": "python",
    "py": "python",
    "node": "nodejs",
    "nodejs": "nodejs",
    "node.js": "nodejs",
    "next": "nextjs",
    "nextjs": "nextjs",
    "react": "react",
    "go": "go",
    "golang": "go",
    "php": "php",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "nginx": "nginx",
    "ruby": "ruby",
    "java": "java",
}

MAJOR_ONLY_PRODUCTS = {"nodejs", "postgresql", "java", "nextjs", "react"}

# Minimal offline fallback so air-gapped environments still get accurate baseline EOL warnings.
STATIC_EOL_FALLBACK: Dict[str, List[Dict[str, Any]]] = {
    "python": [
        {"cycle": "3.13", "eol": "2029-10-31", "latest": "3.13.2"},
        {"cycle": "3.12", "eol": "2028-10-31", "latest": "3.12.9"},
        {"cycle": "3.11", "eol": "2027-10-31", "latest": "3.11.11"},
        {"cycle": "3.10", "eol": "2026-10-31", "latest": "3.10.16"},
        {"cycle": "3.9", "eol": "2025-10-31", "latest": "3.9.21"},
        {"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"},
        {"cycle": "3.7", "eol": "2023-06-27", "latest": "3.7.17"},
    ],
    "nodejs": [
        {"cycle": "22", "eol": "2027-04-30", "lts": "2024-10-29", "latest": "22.14.0"},
        {"cycle": "20", "eol": "2026-04-30", "lts": "2023-10-24", "latest": "20.18.3"},
        {"cycle": "18", "eol": "2025-04-30", "lts": "2022-10-25", "latest": "18.20.7"},
        {"cycle": "16", "eol": "2023-09-11", "lts": "2021-10-26", "latest": "16.20.2"},
    ],
    "php": [
        {"cycle": "8.4", "eol": "2028-12-31", "latest": "8.4.4"},
        {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.17"},
        {"cycle": "8.2", "eol": "2026-12-31", "latest": "8.2.27"},
        {"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.31"},
        {"cycle": "8.0", "eol": "2023-11-26", "latest": "8.0.30"},
        {"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
    ],
    "go": [
        {"cycle": "1.24", "eol": False, "latest": "1.24.1"},
        {"cycle": "1.23", "eol": False, "latest": "1.23.7"},
        {"cycle": "1.22", "eol": "2025-02-11", "latest": "1.22.12"},
        {"cycle": "1.21", "eol": "2024-08-13", "latest": "1.21.13"},
    ],
    "nextjs": [
        {"cycle": "16", "eol": False, "latest": "16.4.5"},
        {"cycle": "15", "eol": False, "latest": "15.5.29"},
        {"cycle": "14", "eol": "2025-10-26", "latest": "14.2.35"},
        {"cycle": "13", "eol": "2024-10-25", "latest": "13.5.8"},
        {"cycle": "12", "eol": "2023-10-26", "latest": "12.3.4"},
    ],
    "react": [
        {"cycle": "19", "eol": False, "latest": "19.1.0"},
        {"cycle": "18", "eol": False, "latest": "18.3.1"},
        {"cycle": "17", "eol": "2022-06-14", "latest": "17.0.2"},
    ],
}

_MEM_CACHE: Dict[str, Dict[str, Any]] = {}


def _cache_dir() -> Path:
    override = os.environ.get("REPOAUDT_EOL_CACHE_DIR", "").strip()
    if override:
        return Path(override)
    return Path(tempfile.gettempdir()) / "repoaudt_eol_cache"


def _default_fetcher(url: str, timeout: float) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "RepoAUDT-Mac/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_product_cycles(
    product: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    fetcher: Optional[Callable[[str, float], Any]] = None,
    use_cache: bool = True,
) -> tuple[List[Dict[str, Any]], str]:
    """Return (cycles, source_label) for a runtime product."""
    slug = PRODUCT_ALIASES.get(str(product or "").strip().lower(), "")
    if not slug:
        return [], "unsupported"

    now = time.time()
    if use_cache and slug in _MEM_CACHE:
        cached = _MEM_CACHE[slug]
        if now - cached["ts"] < CACHE_TTL_SECONDS:
            return cached["cycles"], cached["source"]

    cache_file = _cache_dir() / f"{slug}.json"
    stale_cycles: Optional[List[Dict[str, Any]]] = None
    if use_cache and cache_file.exists():
        try:
            payload = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("cycles"), list):
                stale_cycles = payload["cycles"]
                if now - float(payload.get("ts", 0)) < CACHE_TTL_SECONDS:
                    _MEM_CACHE[slug] = {
                        "ts": float(payload["ts"]),
                        "cycles": stale_cycles,
                        "source": "endoflife.date",
                    }
                    return stale_cycles, "endoflife.date"
        except Exception:
            pass

    fetch_fn = fetcher or _default_fetcher
    try:
        data = fetch_fn(ENDOFLIFE_API_TEMPLATE.format(product=slug), timeout)
        if isinstance(data, list) and all(isinstance(row, dict) for row in data):
            if use_cache:
                _MEM_CACHE[slug] = {"ts": now, "cycles": data, "source": "endoflife.date"}
                try:
                    cache_file.parent.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(
                        json.dumps({"ts": now, "cycles": data}),
                        encoding="utf-8",
                    )
                except Exception:
                    pass
            return data, "endoflife.date"
    except Exception:
        pass

    if stale_cycles:
        return stale_cycles, "endoflife.date (cached)"
    fallback = STATIC_EOL_FALLBACK.get(slug, [])
    return fallback, "static-fallback" if fallback else "unavailable"


def extract_cycle_candidates(product_slug: str, version_text: str) -> List[str]:
    """Extract candidate release cycle strings (e.g. '3.11', '20') from a version spec."""
    text = str(version_text or "").strip()
    if not text:
        return []
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.\d+)?", text)
    if not match:
        return []
    major = match.group(1)
    minor = match.group(2)
    candidates: List[str] = []
    if product_slug in MAJOR_ONLY_PRODUCTS:
        candidates.append(major)
        if minor is not None:
            candidates.append(f"{major}.{minor}")
    else:
        if minor is not None:
            candidates.append(f"{major}.{minor}")
        candidates.append(major)
    return candidates


def _is_cycle_eol(eol_value: Any, today_iso: str) -> Optional[bool]:
    if isinstance(eol_value, bool):
        return eol_value
    if isinstance(eol_value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", eol_value.strip()):
        return eol_value.strip() <= today_iso
    return None


def evaluate_runtime_eol(
    runtime_info: Dict[str, Any],
    *,
    today: Optional[str] = None,
    fetcher: Optional[Callable[[str, float], Any]] = None,
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """Evaluate declared runtimes against endoflife.date release cycles."""
    if not isinstance(runtime_info, dict):
        return []
    today_iso = today or date.today().isoformat()
    results: List[Dict[str, Any]] = []

    for raw_key, raw_ver in runtime_info.items():
        slug = PRODUCT_ALIASES.get(str(raw_key or "").strip().lower(), "")
        if not slug:
            continue
        candidates = extract_cycle_candidates(slug, str(raw_ver or ""))
        if not candidates:
            continue
        cycles, source = fetch_product_cycles(slug, fetcher=fetcher, use_cache=use_cache)
        if not cycles:
            continue

        matched: Optional[Dict[str, Any]] = None
        for cand in candidates:
            matched = next(
                (row for row in cycles if str(row.get("cycle", "")).strip() == cand),
                None,
            )
            if matched:
                break
        if not matched:
            continue

        latest_active = next(
            (row for row in cycles if _is_cycle_eol(row.get("eol"), today_iso) is False),
            cycles[0] if cycles else None,
        )
        eol_val = matched.get("eol")
        is_eol = _is_cycle_eol(eol_val, today_iso)
        eol_over_1y = False
        if is_eol and isinstance(eol_val, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", eol_val.strip()):
            try:
                days_past = (date.fromisoformat(today_iso) - date.fromisoformat(eol_val.strip())).days
                eol_over_1y = days_past >= 365
            except ValueError:
                pass
        results.append(
            {
                "product": slug,
                "declared": str(raw_ver),
                "cycle": str(matched.get("cycle", "")),
                "eol": eol_val,
                "is_eol": is_eol,
                "eol_over_1y": eol_over_1y,
                "latest": matched.get("latest"),
                "latest_active_cycle": str(latest_active.get("cycle", "")) if latest_active else None,
                "source": source,
            }
        )
    return results


def extract_repo_runtime_and_framework_versions(repo_dir: Path) -> Dict[str, str]:
    """Extract major runtime/framework versions from package.json, .nvmrc, Dockerfile, and pyproject.toml."""
    found: Dict[str, str] = {}
    if not repo_dir or not repo_dir.exists():
        return found

    pkg_json = repo_dir / "package.json"
    if pkg_json.is_file():
        try:
            pdata = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            engines = pdata.get("engines") or {}
            if engines.get("node"):
                found["nodejs"] = str(engines["node"])
            deps = {}
            deps.update(pdata.get("dependencies") or {})
            deps.update(pdata.get("devDependencies") or {})
            if deps.get("next"):
                found["nextjs"] = str(deps["next"])
            if deps.get("react"):
                found["react"] = str(deps["react"])
        except Exception:
            pass

    nvmrc = repo_dir / ".nvmrc"
    if nvmrc.is_file() and "nodejs" not in found:
        try:
            txt = nvmrc.read_text(encoding="utf-8", errors="ignore").strip()
            if txt:
                found["nodejs"] = txt
        except OSError:
            pass

    pyproject = repo_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            txt = pyproject.read_text(encoding="utf-8", errors="ignore")
            m_py = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', txt)
            if m_py:
                found["python"] = m_py.group(1)
        except OSError:
            pass

    for df in repo_dir.rglob("Dockerfile*"):
        if not df.is_file():
            continue
        try:
            txt = df.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m_node in re.finditer(r"^\s*FROM\s+(?:node):(\d+(?:\.\d+)?)", txt, re.MULTILINE | re.IGNORECASE):
            found.setdefault("nodejs", m_node.group(1))
        for m_py in re.finditer(r"^\s*FROM\s+(?:python):(\d+\.\d+)", txt, re.MULTILINE | re.IGNORECASE):
            found.setdefault("python", m_py.group(1))

    return found
