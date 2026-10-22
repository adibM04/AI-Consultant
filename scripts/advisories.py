#!/usr/bin/env python3
"""Advisory watch: tell a developer about NEW published problems that affect THEIR stack.

Facts come only from authoritative feeds, never from a model and never from news text:

  OSV.dev            known vulnerabilities for exact package versions (npm, PyPI, Packagist, ...)
  CISA KEV           vulnerabilities confirmed as exploited in the wild ("act now")
  endoflife.date     runtimes and frameworks that have stopped getting security fixes

It reads the project's lockfiles, pinned requirements, Dockerfiles and version files to know what
runs, then reports what applies. Honesty rules enforced here:

  * Only exact, pinned versions are matched against OSV. Anything unpinned is COUNTED and reported
    as not checked, because matching a version range would invent alerts.
  * Runtime flaws on the exploited list cannot be matched to your exact version, so they are shown
    as "possibly affected, confirm your version", never as "you are affected".
  * A feed that cannot be reached is reported as unreachable. "Nothing found" is never printed when
    a feed was down, and no output ever says you are safe.

Sends only package names, versions and ecosystem names to osv.dev. No code, no paths.

    python3 advisories.py [--root .] [--format text|json|markdown] [--only-new] [--mark-seen]
    python3 advisories.py --hook          # for the session-start hook: silent unless something new

Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_packages  # noqa: E402  (shared SKIP_DIRS)

USER_AGENT = "ai-consultant-advisories/0.1 (+https://github.com/adibM04/AI-Consultant)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_URL = "https://endoflife.date/api/{product}.json"

MAX_PACKAGES = 1000
MAX_VULN_DETAILS = 80
KEV_WINDOW_DAYS = 60
EOL_SOON_DAYS = 90
HOOK_BUDGET_SECONDS = 12.0
CACHE_TTL_HOURS = 24

ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "packagist": "Packagist"}
# runtime product -> (endoflife.date product, name the CISA list uses, how many version parts make a "cycle")
RUNTIMES = {"php": ("php", "php", 2), "node": ("nodejs", "node.js", 1), "python": ("python", "python", 2)}
# packages worth an end-of-life check, as (ecosystem, name) -> (endoflife.date product, cycle parts)
FRAMEWORKS = {("packagist", "laravel/framework"): ("laravel", 1), ("pypi", "django"): ("django", 2),
              ("packagist", "symfony/symfony"): ("symfony", 2)}

PRIORITY_LABEL = {0: "ACTIVELY EXPLOITED", 1: "HIGH", 2: "MEDIUM", 3: "LOW / INFO"}
CHECKLIST = {"package-vuln": ["SEC-04", "MNT-04"], "runtime-eol": ["MNT-05"], "runtime-exploited": ["MNT-05", "SEC-04"]}


# ------------------------------------------------------------------ network

def http(method: str, url: str, body: dict | None = None, timeout: float = 15.0):
    """Return (status, parsed_json_or_None). Status 0 means the network failed."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read(40_000_000))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return 0, None


class Feeds:
    """The three feeds, with an optional overall time budget (used by the session hook)."""

    def __init__(self, fetch=http, budget: float | None = None):
        self.fetch, self.deadline = fetch, (time.monotonic() + budget) if budget else None
        self.status = {"osv": "not used", "kev": "not used", "eol": "not used"}

    def _call(self, method, url, body=None):
        timeout = 15.0
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0.5:
                return 0, None
        return self.fetch(method, url, body, timeout)

    def osv_batch(self, queries: list[dict]) -> list[list[str]] | None:
        out: list[list[str]] = []
        for i in range(0, len(queries), 500):
            status, doc = self._call("POST", OSV_BATCH, {"queries": queries[i:i + 500]})
            if status != 200 or not isinstance(doc, dict) or len(doc.get("results", [])) != len(queries[i:i + 500]):
                self.status["osv"] = "unreachable"
                return None
            out += [[v["id"] for v in (r.get("vulns") or []) if "id" in v] for r in doc["results"]]
        self.status["osv"] = "ok"
        return out

    def osv_vuln(self, vuln_id: str) -> dict | None:
        status, doc = self._call("GET", OSV_VULN + vuln_id)
        return doc if status == 200 and isinstance(doc, dict) else None

    def kev(self) -> list[dict] | None:
        status, doc = self._call("GET", KEV_URL)
        if status != 200 or not isinstance(doc, dict) or "vulnerabilities" not in doc:
            self.status["kev"] = "unreachable"
            return None
        self.status["kev"] = "ok"
        return doc["vulnerabilities"]

    def eol(self, product: str) -> list[dict] | None:
        status, doc = self._call("GET", EOL_URL.format(product=product))
        if status != 200 or not isinstance(doc, list):
            self.status["eol"] = "unreachable" if self.status["eol"] != "ok" else "partial"
            return None
        if self.status["eol"] != "partial":
            self.status["eol"] = "ok"
        return doc


# ------------------------------------------------------------------ inventory

def _find(root: Path, names: set[str] | None = None, prefix: str | None = None):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(p in verify_packages.SKIP_DIRS for p in path.relative_to(root).parts[:-1]):
            continue
        if (names and path.name in names) or (prefix and path.name.startswith(prefix)):
            yield path


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: dict[tuple[str, str], None] = {}
    for key, meta in (data.get("packages") or {}).items():
        if key and isinstance(meta, dict) and meta.get("version") and not meta.get("link"):
            out[(key.rsplit("node_modules/", 1)[-1], meta["version"])] = None

    def walk(deps):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out[(name, meta["version"])] = None
                walk(meta.get("dependencies"))
    if not data.get("packages"):
        walk(data.get("dependencies"))
    return list(out)


def parse_composer_lock(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for section in ("packages", "packages-dev"):
        for p in data.get(section) or []:
            version = str(p.get("version", "")).lstrip("v")
            if p.get("name") and re.match(r"^\d", version):  # skips dev-master and branch aliases
                out.append((p["name"], version))
    return out


def parse_requirements_pins(text: str) -> list[tuple[str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$", line)
        if m:
            out.append((re.sub(r"[-_.]+", "-", m.group(1).lower()), m.group(2)))
    return out


def lowest_cycle(constraint: str, parts: int) -> str | None:
    """Lowest version a constraint such as '^8.1 || ^8.3' allows, cut to a release cycle ('8.1')."""
    lows = []
    for alt in re.split(r"\|\|", constraint):
        m = re.search(r"(\d+(?:\.\d+)*)", alt)
        if m:
            lows.append(tuple(int(x) for x in m.group(1).split(".")))
    if not lows:
        return None
    low = min(lows)
    low = low + (0,) * (parts - len(low))
    return ".".join(str(x) for x in low[:parts])


def cycle_of(version: str, parts: int) -> str | None:
    m = re.match(r"^v?(\d+(?:\.\d+)*)", version.strip())
    if not m:
        return None
    bits = m.group(1).split(".")
    return ".".join((bits + ["0"] * parts)[:parts])


def detect_runtimes(root: Path) -> list[dict]:
    found: list[dict] = []

    def add(product, cycle, exact, source):
        if cycle:
            found.append({"product": product, "cycle": cycle, "exact": exact, "source": source})

    for path in _find(root, {"composer.json"}):
        try:
            req = (json.loads(_read(path)).get("require") or {}).get("php")
        except json.JSONDecodeError:
            req = None
        if req:
            add("php", lowest_cycle(str(req), 2), False, f"{path.relative_to(root)} (require.php {req})")
    for path in _find(root, {".php-version"}):
        add("php", cycle_of(_read(path), 2), True, str(path.relative_to(root)))
    for path in _find(root, {"package.json"}):
        try:
            eng = (json.loads(_read(path)).get("engines") or {}).get("node")
        except json.JSONDecodeError:
            eng = None
        if eng:
            add("node", lowest_cycle(str(eng), 1), False, f"{path.relative_to(root)} (engines.node {eng})")
    for path in _find(root, {".nvmrc"}):
        add("node", cycle_of(_read(path).strip().lstrip("v"), 1), True, str(path.relative_to(root)))
    for path in _find(root, {".python-version"}):
        add("python", cycle_of(_read(path), 2), True, str(path.relative_to(root)))
    for path in _find(root, {"runtime.txt"}):
        m = re.match(r"python-(\d+\.\d+)", _read(path).strip())
        add("python", m.group(1) if m else None, True, str(path.relative_to(root)))
    for path in _find(root, prefix="Dockerfile"):
        for m in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?(php|node|python):(\d+(?:\.\d+)*)", _read(path), re.M | re.I):
            product = m.group(1).lower()
            add(product, cycle_of(m.group(2), RUNTIMES[product][2]), True, f"{path.relative_to(root)} (FROM {m.group(0).split('FROM')[1].strip()})")
    # one entry per product and source; keep distinct sources so the report can say where it came from
    seen, unique = set(), []
    for r in found:
        key = (r["product"], r["cycle"], r["source"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def declared_composer(root: Path) -> set[tuple[str, str]]:
    """Packagist packages named in composer.json (the shared collector only knows npm and PyPI)."""
    out = set()
    for path in _find(root, {"composer.json"}):
        try:
            data = json.loads(_read(path))
        except json.JSONDecodeError:
            continue
        for section in ("require", "require-dev"):
            for name in (data.get(section) or {}):
                if "/" in name:  # skips php, ext-*, lib-*
                    out.add(("packagist", name.lower()))
    return out


def inventory(root: Path) -> dict:
    pinned: dict[tuple[str, str, str], str] = {}
    for path in _find(root, {"package-lock.json"}):
        for name, version in parse_package_lock(_read(path)):
            pinned[("npm", name, version)] = str(path.relative_to(root))
    for path in _find(root, {"composer.lock"}):
        for name, version in parse_composer_lock(_read(path)):
            pinned[("packagist", name, version)] = str(path.relative_to(root))
    for path in _find(root, prefix="requirements"):
        if path.suffix == ".txt":
            for name, version in parse_requirements_pins(_read(path)):
                pinned[("pypi", name, version)] = str(path.relative_to(root))
    declared = {(p["ecosystem"], p["name"]) for p in verify_packages.collect(root)} | declared_composer(root)
    pinned_names = {(e, n.lower()) for e, n, _ in pinned}
    return {
        "packages": [{"ecosystem": e, "name": n, "version": v, "source": s} for (e, n, v), s in sorted(pinned.items())],
        "unpinned": sorted(f"{e}:{n}" for e, n in declared - pinned_names if e in ECOSYSTEM and n),
        "runtimes": detect_runtimes(root),
    }


# ------------------------------------------------------------------ severity

def cvss3_score(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string, or None if it is not a v3 vector."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av, ac = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]], {"L": .77, "H": .44}[m["AC"]]
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        ui = {"N": .85, "R": .62}[m["UI"]]
        cia = [{"H": .56, "L": .22, "N": 0}[m[k]] for k in ("C", "I", "A")]
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
    return math.ceil(raw * 10 - 1e-9) / 10


def severity_label(vuln: dict) -> str:
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return "MEDIUM" if label == "MODERATE" else label
    for s in vuln.get("severity") or []:
        score = cvss3_score(str(s.get("score", "")))
        if score is not None:
            return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return "UNKNOWN"


def vkey(version: str) -> tuple[int, ...]:
    """Numeric sort key: '2.2.28' -> (2, 2, 28). Pre-release and build suffixes are ignored."""
    return tuple(int(n) for n in re.findall(r"\d+", re.split(r"[-+_a-zA-Z]", str(version).lstrip("vV"), maxsplit=1)[0])[:5])


def choose_fix(installed: str, fixed: list[str]) -> tuple[str | None, bool]:
    """The nearest fixed version ABOVE the installed one, preferring the same major version.

    OSV lists one fixed version per release branch (1.11.23, 2.2.4, 4.2.16...). Taking the first, or the
    lowest, would tell a Django 2.2 user to move to 1.11, which is a downgrade. Returns (version, is_major_jump).
    """
    inst = vkey(installed)
    above = sorted((vkey(f), f) for f in fixed if vkey(f) and vkey(f) > inst)
    if not above:
        return None, False
    same = [f for k, f in above if k[:1] == inst[:1]]
    if same:
        return same[0], False
    return above[0][1], True


def fixed_versions(vuln: dict, package: str, ecosystem: str) -> list[str]:
    out = []
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name", "").lower() != package.lower() or p.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(out))


# ------------------------------------------------------------------ assessment

def _eol_date(value) -> dt.date | None | bool:
    """endoflife.date uses a date string, or true/false. Returns a date, True (already EOL) or None (not EOL)."""
    if value is True:
        return True
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def eol_alert(product: str, cycle: str, exact: bool, source: str, cycles: list[dict], today: dt.date):
    row = next((c for c in cycles if str(c.get("cycle")) == cycle), None)
    if row is None:
        return None
    eol = _eol_date(row.get("eol"))
    supported = [c for c in cycles if _eol_date(c.get("eol")) in (None,) or (isinstance(_eol_date(c.get("eol")), dt.date) and _eol_date(c.get("eol")) > today)]
    newest = str(supported[0]["cycle"]) if supported else None
    what = f"{product} {cycle}" if exact else f"{product} {cycle} (the lowest version your project declares)"
    if eol is True or (isinstance(eol, dt.date) and eol <= today):
        when = "" if eol is True else f" on {eol.isoformat()}"
        return {"priority": 1, "kind": "runtime-eol", "title": f"{what} stopped receiving security fixes{when}",
                "action": f"Plan an upgrade to a supported version{f' (newest supported: {newest})' if newest else ''}. Unfixed flaws stay open forever.",
                "source": source, "url": f"https://endoflife.date/{product}", "key": f"eol:{product}:{cycle}", "exact": exact}
    if isinstance(eol, dt.date) and (eol - today).days <= EOL_SOON_DAYS:
        return {"priority": 2, "kind": "runtime-eol", "title": f"{what} stops receiving security fixes on {eol.isoformat()} ({(eol - today).days} days)",
                "action": f"Schedule the upgrade now{f' (newest supported: {newest})' if newest else ''}.",
                "source": source, "url": f"https://endoflife.date/{product}", "key": f"eol:{product}:{cycle}", "exact": exact}
    return None


def rollup(alerts: list[dict]) -> list[dict]:
    """One line per package: the single same-major upgrade that clears most of its advisories."""
    groups: dict[tuple, list[dict]] = {}
    for a in alerts:
        if a["kind"] == "package-vuln":
            groups.setdefault((a["ecosystem"], a["package"], a["version"]), []).append(a)
    out = []
    for (eco, name, version), items in groups.items():
        same = [a for a in items if a.get("fix") and not a.get("major_jump")]
        target = max((a["fix"] for a in same), key=vkey) if same else None
        majors = [a for a in items if a.get("fix") and a.get("major_jump")]
        out.append({"package": name, "version": version, "ecosystem": eco, "advisories": len(items),
                    "upgrade_to": target, "clears": len(same),
                    "needs_major_upgrade": len(majors),
                    "smallest_major_fix": min((a["fix"] for a in majors), key=vkey) if majors and not target else None,
                    "no_fix_listed": sum(1 for a in items if not a.get("fix")),
                    "worst_priority": min(a["priority"] for a in items)})
    return sorted(out, key=lambda r: (r["worst_priority"], -r["advisories"], r["package"]))


def collect(root: Path, feeds: Feeds, today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    inv = inventory(root)
    alerts: list[dict] = []

    kev = feeds.kev()
    kev_ids = {k["cveID"] for k in (kev or []) if "cveID" in k}

    # --- package vulnerabilities (exact versions only)
    pkgs = inv["packages"][:MAX_PACKAGES]
    skipped_over_cap = max(0, len(inv["packages"]) - MAX_PACKAGES)
    osv_checked = 0
    if pkgs:
        queries = [{"package": {"name": p["name"], "ecosystem": ECOSYSTEM[p["ecosystem"]]}, "version": p["version"]} for p in pkgs]
        results = feeds.osv_batch(queries)
        if results is not None:
            osv_checked = len(pkgs)
            details: dict[str, dict | None] = {}
            pairs = [(p, vid) for p, ids in zip(pkgs, results) for vid in ids]
            for _, vid in pairs[:MAX_VULN_DETAILS * 4]:
                if vid not in details and len(details) < MAX_VULN_DETAILS:
                    details[vid] = feeds.osv_vuln(vid)
            seen: set[tuple] = set()
            for p, vid in pairs:
                v = details.get(vid)
                if not v or v.get("withdrawn"):
                    continue
                ids = {vid, *v.get("aliases", [])}
                key = (p["ecosystem"], p["name"], p["version"], min(ids))
                if any((p["ecosystem"], p["name"], p["version"], i) in seen for i in ids):
                    continue
                seen.update((p["ecosystem"], p["name"], p["version"], i) for i in ids)
                exploited = bool(ids & kev_ids)
                sev = severity_label(v)
                fixed = fixed_versions(v, p["name"], ECOSYSTEM[p["ecosystem"]])
                fix, jump = choose_fix(p["version"], fixed)
                cves = sorted(i for i in ids if i.startswith("CVE-"))
                prio = 0 if exploited else 1 if sev in ("CRITICAL", "HIGH") else 2 if sev == "MEDIUM" else 3
                alerts.append({
                    "priority": prio, "kind": "package-vuln", "exploited": exploited, "severity": sev,
                    "title": f"{p['name']} {p['version']}: {(v.get('summary') or vid)[:140]}",
                    "ids": sorted(ids), "cves": cves, "package": p["name"], "version": p["version"], "ecosystem": p["ecosystem"],
                    "fixed_in": fixed, "fix": fix, "major_jump": jump, "published": v.get("published"), "modified": v.get("modified"),
                    "action": (f"Upgrade {p['name']} to {fix} or later." + (" This is a major version upgrade: read the changelog first." if jump else "")
                               if fix else f"No fixed version above {p['version']} is listed; read the advisory for a workaround."),
                    "source": p["source"], "url": f"https://osv.dev/vulnerability/{vid}", "key": "vuln:" + p["ecosystem"] + ":" + p["name"] + "@" + p["version"] + ":" + min(ids),
                })

    # --- runtimes and frameworks: end of life
    cache: dict[str, list[dict] | None] = {}
    def cycles_for(product):
        if product not in cache:
            cache[product] = feeds.eol(product)
        return cache[product]

    runtimes_checked = 0
    for r in inv["runtimes"]:
        eol_product = RUNTIMES[r["product"]][0]
        cycles = cycles_for(eol_product)
        if cycles is None:
            continue
        runtimes_checked += 1
        a = eol_alert(eol_product, r["cycle"], r["exact"], r["source"], cycles, today)
        if a:
            alerts.append(a)
    for p in inv["packages"]:
        fw = FRAMEWORKS.get((p["ecosystem"], p["name"]))
        if fw:
            cycles = cycles_for(fw[0])
            cyc = cycle_of(p["version"], fw[1])
            if cycles is not None and cyc:
                runtimes_checked += 1
                a = eol_alert(fw[0], cyc, True, p["source"], cycles, today)
                if a:
                    alerts.append(a)

    # --- runtime flaws confirmed as exploited (cannot be matched to an exact version)
    for k in kev or []:
        try:
            added = dt.date.fromisoformat(k.get("dateAdded", ""))
        except ValueError:
            continue
        if (today - added).days > KEV_WINDOW_DAYS:
            continue
        product = str(k.get("product", "")).lower()
        vendor = str(k.get("vendorProject", "")).lower()
        for r in inv["runtimes"]:
            name = RUNTIMES[r["product"]][1]
            if name in (product, vendor) or product.startswith(name + " ") or vendor == name:
                alerts.append({
                    "priority": 0, "kind": "runtime-exploited", "exploited": True,
                    "title": f"{k.get('vulnerabilityName') or k['cveID']} is being exploited, and your project uses {r['product']} {r['cycle']}",
                    "ids": [k["cveID"]], "cves": [k["cveID"]],
                    "action": "POSSIBLY AFFECTED: this list does not say which versions are vulnerable. Open the advisory, compare it with your exact version, and patch if it matches. "
                              + (k.get("requiredAction") or ""),
                    "source": r["source"], "published": k.get("dateAdded"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{k['cveID']}", "key": f"kev:{k['cveID']}:{r['product']}",
                })
                break

    alerts.sort(key=lambda a: (a["priority"], a["title"]))
    coverage = {
        "packages_checked": osv_checked, "packages_over_cap": skipped_over_cap,
        "packages_unpinned_not_checked": len(inv["unpinned"]),
        "runtimes_found": len(inv["runtimes"]), "eol_checks_done": runtimes_checked,
        "feeds": dict(feeds.status),
    }
    return {"generated": today.isoformat(), "alerts": alerts, "rollup": rollup(alerts), "coverage": coverage, "unpinned": inv["unpinned"][:50]}


# ------------------------------------------------------------------ state, cache, rendering

def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def mark_new(result: dict, state: dict) -> dict:
    seen = set(state.get("seen", []))
    for a in result["alerts"]:
        a["new"] = a["key"] not in seen
    return result


def feeds_note(cov: dict) -> list[str]:
    notes = []
    down = [name for name, st in cov["feeds"].items() if st in ("unreachable", "partial")]
    if down:
        notes.append("Could not reach: " + ", ".join(down) + ". Results below are INCOMPLETE; this is not an all-clear.")
    if cov["packages_unpinned_not_checked"]:
        notes.append(f"{cov['packages_unpinned_not_checked']} declared packages have no pinned version (no lockfile or == pin), so they were not checked. "
                     "Commit a lockfile to include them.")
    if cov["packages_over_cap"]:
        notes.append(f"{cov['packages_over_cap']} pinned packages were over the {MAX_PACKAGES} limit and were not checked.")
    return notes


def rollup_line(r: dict) -> str:
    head = f"{r['package']} {r['version']}: {r['advisories']} advisor{'y' if r['advisories'] == 1 else 'ies'}."
    if r["upgrade_to"]:
        tail = f" Upgrade to {r['upgrade_to']} to clear {r['clears']}"
        extra = r["needs_major_upgrade"] + r["no_fix_listed"]
        tail += f"; {extra} more need a major-version upgrade or have no fix listed." if extra else "."
        return head + tail
    if r["smallest_major_fix"]:
        return head + f" No fix in your major version; the smallest fix is {r['smallest_major_fix']} (a major-version upgrade: read the changelog)."
    return head + " No fixed version above yours is listed."


def render_text(result: dict, only_new: bool = False) -> str:
    cov, alerts = result["coverage"], result["alerts"]
    if only_new:
        alerts = [a for a in alerts if a.get("new")]
    lines = [f"Advisory watch, {result['generated']}", ""]
    if result.get("rollup") and alerts:
        lines += ["WHAT TO UPGRADE FIRST", ""] + [f"  {rollup_line(r)}" for r in result["rollup"]] + [""]
    if not alerts:
        lines.append("No " + ("new " if only_new else "") + "advisories matched what could be checked.")
    for prio in (0, 1, 2, 3):
        group = [a for a in alerts if a["priority"] == prio]
        if not group:
            continue
        lines += [f"{PRIORITY_LABEL[prio]} ({len(group)})", ""]
        for a in group:
            lines.append(f"  {'[NEW] ' if a.get('new') else ''}{a['title']}")
            lines.append(f"    Do: {a['action']}")
            lines.append(f"    Source: {a['url']}" + (f"   Found in: {a['source']}" if a.get("source") else ""))
            lines.append("")
    lines.append(f"Checked: {cov['packages_checked']} pinned packages, {cov['eol_checks_done']} runtime or framework end-of-life checks.")
    lines += feeds_note(cov)
    lines.append("This reports published advisories for the versions it could read. It cannot tell you that you are safe.")
    return "\n".join(lines) + "\n"


def render_markdown(result: dict, only_new: bool = False) -> str:
    cov, alerts = result["coverage"], result["alerts"]
    shown = [a for a in alerts if a.get("new")] if only_new else alerts
    out = ["<!-- ai-consultant-advisories -->", f"### Security advisories affecting this project ({result['generated']})", ""]
    if result.get("rollup") and not only_new:
        out += ["**What to upgrade first**", ""] + [f"- {rollup_line(r)}" for r in result["rollup"]] + [""]
    if not shown:
        out.append("Nothing new matched what could be checked.")
    for prio in (0, 1, 2, 3):
        group = [a for a in shown if a["priority"] == prio]
        if not group:
            continue
        out += [f"**{PRIORITY_LABEL[prio]}**", ""]
        for a in group:
            out.append(f"- {'🆕 ' if a.get('new') else ''}{a['title']}  \n  **Do:** {a['action']}  \n  [{a['url']}]({a['url']})")
        out.append("")
    out += [f"<sub>Checked {cov['packages_checked']} pinned packages and {cov['eol_checks_done']} end-of-life entries."]
    out += [" " + n for n in feeds_note(cov)]
    out += [" Published advisories only: this cannot tell you that you are safe. "
            "[AI-Consultant](https://github.com/adibM04/AI-Consultant)</sub>"]
    return "\n".join(out).replace("\n </sub>", "</sub>") + "\n"


def hook_message(result: dict) -> str | None:
    new = [a for a in result["alerts"] if a.get("new")]
    if not new:
        return None
    exploited = sum(1 for a in new if a["priority"] == 0)
    top = new[0]["title"]
    head = f"AI-Consultant: {len(new)} new security advisor{'y affects' if len(new) == 1 else 'ies affect'} this project"
    if exploited:
        head += f" ({exploited} actively exploited)"
    return f"{head}. First: {top[:120]}. Run /ai-consultant:consult-alerts for what to do."


def run_hook(root: Path, fetch=http, now: float | None = None, today: dt.date | None = None) -> str | None:
    """Session-start reminder. Silent unless the project opted in AND something new applies. Never raises."""
    try:
        cfg = load_json(root / ".consultant" / "alerts.json", {})
        if not cfg.get("enabled"):
            return None
        now = time.time() if now is None else now
        cache_path, state_path = root / ".consultant" / "cache" / "advisories.json", root / ".consultant" / "alerts-state.json"
        cached = load_json(cache_path, {})
        if cached.get("result") and now - cached.get("at", 0) < CACHE_TTL_HOURS * 3600:
            result = cached["result"]
        else:
            result = collect(root, Feeds(fetch, HOOK_BUDGET_SECONDS), today)
            if all(st != "unreachable" for st in result["coverage"]["feeds"].values()):
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(json.dumps({"at": now, "result": result}), encoding="utf-8")
        state = load_json(state_path, {})
        mark_new(result, state)
        msg = hook_message(result)
        if msg:
            state["seen"] = sorted(set(state.get("seen", [])) | {a["key"] for a in result["alerts"]})
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        return msg
    except Exception:  # a reminder must never break a session
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    ap.add_argument("--only-new", action="store_true", help="show only advisories not seen before")
    ap.add_argument("--mark-seen", action="store_true", help="remember what was shown, so it is 'new' only once")
    ap.add_argument("--state", type=Path, help="seen-state file (default .consultant/alerts-state.json)")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--hook", action="store_true", help="session-start mode: silent unless something new applies")
    ap.add_argument("--offline", action="store_true", help="make no network requests (every feed is reported unreachable)")
    ap.add_argument("--render-from", type=Path, help="render a previously saved --format json result instead of querying the feeds")
    ap.add_argument("--fail-on", choices=("exploited", "high", "none"), default="none", help="exit 1 at this priority (for CI)")
    args = ap.parse_args()
    root = args.root.resolve()

    if args.hook:
        msg = run_hook(root)
        if msg:
            sys.stdout.write(json.dumps({"systemMessage": msg}) + "\n")
        return 0

    state_path = args.state or (root / ".consultant" / "alerts-state.json")
    if args.render_from:
        saved = load_json(args.render_from, None)
        if not isinstance(saved, dict) or "alerts" not in saved:
            print(f"error: {args.render_from} is not a saved advisory result", file=sys.stderr)
            return 2
        result = mark_new(saved, load_json(state_path, {}))
    else:
        feeds = Feeds(lambda *a, **k: (0, None)) if args.offline else Feeds()
        result = mark_new(collect(root, feeds), load_json(state_path, {}))
    text = (json.dumps(result, indent=2) + "\n" if args.format == "json" else
            render_markdown(result, args.only_new) if args.format == "markdown" else render_text(result, args.only_new))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if args.mark_seen:
        state = load_json(state_path, {})
        state["seen"] = sorted(set(state.get("seen", [])) | {a["key"] for a in result["alerts"]})
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    worst = min((a["priority"] for a in result["alerts"]), default=9)
    if (args.fail_on == "exploited" and worst == 0) or (args.fail_on == "high" and worst <= 1):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
