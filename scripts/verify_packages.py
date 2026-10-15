#!/usr/bin/env python3
"""Check that every declared dependency exists and is the one you meant.

AI assistants invent package names ("slopsquatting") and mistype real ones.
Attackers register those names. This script reads dependency manifests,
asks the public npm / PyPI registries about each package, and flags:

    NOT_FOUND           not on the registry: hallucinated, private, or free for an attacker to claim
    TYPOSQUAT_SUSPECT   one or two edits away from a very popular package
    NEW_PACKAGE         first published recently
    FEW_DOWNLOADS       tiny weekly download count (npm only; skipped if the API is unreachable)
    NO_REPOSITORY       no source repository linked
    DEPRECATED          marked deprecated by its maintainer
    ABANDONED           no release for several years
    INVALID_NAME        not a legal package name, so not queried

Privacy: only package NAMES are sent, to registry.npmjs.org, api.npmjs.org
and pypi.org. No source code or paths leave the machine. Use --offline to
send nothing (then only INVALID_NAME and TYPOSQUAT_SUSPECT can fire).

Standard library only. Never executes or installs anything from the project.

    python3 verify_packages.py [--root .] [--out .consultant/facts/packages.json] [--offline]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "dist", "build", "__pycache__",
             ".next", ".tox", "vendor", "site-packages", ".consultant"}
MAX_MANIFESTS = 200
USER_AGENT = "ai-consultant-package-verifier/0.1 (+https://github.com/adibM04/AI-Consultant)"

NEW_DAYS = 30
FEW_DOWNLOADS = 100
ABANDONED_YEARS = 3

NPM_NAME = re.compile(r"^(@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$")
PYPI_NAME = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")

POPULAR = {
    "npm": set("""react react-dom next vue express lodash axios typescript webpack vite eslint prettier jest mocha
chalk commander moment dayjs uuid dotenv cors body-parser mongoose mongodb pg mysql mysql2 sequelize prisma redis
ioredis socket.io jsonwebtoken bcrypt bcryptjs passport helmet morgan nodemon tailwindcss postcss autoprefixer rxjs
zod yup joi classnames clsx swr redux react-redux react-router react-router-dom zustand formik stripe openai
firebase firebase-admin nodemailer multer cookie-parser express-session ws request async bluebird underscore yargs
glob rimraf mkdirp semver debug minimist inquirer ora cheerio puppeteer playwright cypress vitest tsx ts-node
esbuild rollup svelte solid-js preact graphql fastify koa sharp jimp marked date-fns luxon immer ramda validator
sanitize-html dompurify node-fetch got superagent form-data busboy formidable compression csurf express-rate-limit
winston pino bunyan cross-env concurrently husky lint-staged framer-motion lucide-react three d3 chart.js recharts
leaflet socket.io-client bull bullmq knex typeorm drizzle-orm better-sqlite3 sqlite3 aws-sdk twilio resend
@supabase/supabase-js @anthropic-ai/sdk @prisma/client @clerk/nextjs @trpc/server @tanstack/react-query
""".split()),
    "pypi": set("""requests numpy pandas django flask fastapi uvicorn gunicorn sqlalchemy alembic psycopg2
psycopg2-binary psycopg pydantic pytest boto3 botocore urllib3 certifi setuptools wheel pip six python-dateutil
pyyaml jinja2 markupsafe click werkzeug cryptography pyjwt bcrypt passlib celery redis httpx aiohttp beautifulsoup4
lxml pillow matplotlib scipy scikit-learn tensorflow torch openai anthropic langchain stripe sentry-sdk
python-dotenv tqdm rich typer black flake8 mypy isort ruff pylint coverage tox selenium playwright
djangorestframework django-cors-headers whitenoise pymongo mysqlclient pymysql supabase firebase-admin
google-cloud-storage twilio sendgrid python-multipart orjson ujson itsdangerous attrs packaging idna
charset-normalizer colorama docutils pygments tomli toml typing-extensions zipp importlib-metadata protobuf grpcio
google-api-python-client pyopenssl paramiko fabric psutil regex decorator networkx sympy openpyxl xlrd xlsxwriter
python-slugify markdown bleach python-jose authlib email-validator tenacity structlog loguru pytest-cov
pytest-asyncio
""".split()),
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


# ---------------------------------------------------------------- parsing

def normalize(eco: str, name: str) -> str:
    name = name.strip()
    return re.sub(r"[-_.]+", "-", name.lower()) if eco == "pypi" else name.lower()


def _walk_manifests(root: Path):
    found = 0
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if not path.is_file():
            continue
        n = path.name
        if n == "package.json" or n == "pyproject.toml" or (n.startswith("requirements") and n.endswith(".txt")):
            found += 1
            if found > MAX_MANIFESTS:
                return
            yield path


def parse_package_json(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec = str(spec)
            real = name
            if spec.startswith("npm:"):  # alias: "foo": "npm:bar@^1"
                real = spec[4:].rsplit("@", 1)[0] if "@" in spec[5:] else spec[4:]
            non_registry = bool(re.match(r"^(git\+|git://|github:|gitlab:|bitbucket:|https?:|file:|link:|workspace:|portal:)", spec)
                                or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", spec))
            yield {"ecosystem": "npm", "name": real, "spec": spec, "kind": "dev" if section == "devDependencies" else "prod",
                   "non_registry": non_registry}


def parse_requirements(path: Path):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "-i")):
            continue
        if line.startswith("-e") or "://" in line or line.startswith((".", "/")):
            yield {"ecosystem": "pypi", "name": line, "spec": line, "kind": "prod", "non_registry": True}
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            yield {"ecosystem": "pypi", "name": m.group(1), "spec": line, "kind": "prod", "non_registry": False}


def parse_pyproject(path: Path):
    if tomllib is None:
        return
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return
    project = data.get("project") or {}
    reqs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        reqs.extend(group)
    for r in reqs:
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", str(r))
        if m:
            yield {"ecosystem": "pypi", "name": m.group(1), "spec": str(r), "kind": "prod", "non_registry": "@" in str(r)}
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section) or {}).items():
            if name.lower() == "python":
                continue
            nr = isinstance(spec, dict) and any(k in spec for k in ("git", "path", "url"))
            yield {"ecosystem": "pypi", "name": name, "spec": str(spec), "kind": "prod", "non_registry": nr}


def collect(root: Path):
    """Return a de-duplicated list of declared packages with the manifests that declare them."""
    merged: dict[tuple[str, str], dict] = {}
    for path in _walk_manifests(root):
        rel = str(path.relative_to(root))
        if path.name == "package.json":
            entries = parse_package_json(path)
        elif path.name == "pyproject.toml":
            entries = parse_pyproject(path)
        else:
            entries = parse_requirements(path)
        for e in entries or ():
            key = (e["ecosystem"], e["name"] if e["non_registry"] and e["ecosystem"] == "pypi" and "://" in e["name"] else normalize(e["ecosystem"], e["name"]))
            cur = merged.setdefault(key, {"ecosystem": e["ecosystem"], "name": key[1], "declared_in": [],
                                          "specs": [], "non_registry": e["non_registry"]})
            if rel not in cur["declared_in"]:
                cur["declared_in"].append(rel)
            if e["spec"] not in cur["specs"]:
                cur["specs"].append(e["spec"])
            cur["non_registry"] = cur["non_registry"] and e["non_registry"]
    return sorted(merged.values(), key=lambda p: (p["ecosystem"], p["name"]))


# ---------------------------------------------------------------- typosquat

def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (insert, delete, substitute, adjacent swap)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def typosquat_target(eco: str, name: str):
    """Return the popular package this name imitates, or None."""
    popular = POPULAR[eco]
    if name in popular:
        return None
    for target in sorted(popular):
        if abs(len(target) - len(name)) > 2:
            continue
        dist = edit_distance(name, target)
        if (dist == 1 and len(target) >= 5) or (dist == 2 and len(target) >= 9 and len(name) >= 9):
            return target
    return None


# ---------------------------------------------------------------- registries

def http_json(url: str, timeout: float = 15.0):
    """Return (status, parsed_json_or_None). status is the HTTP code, or 0 for network failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(30_000_000)
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return 0, None


def _parse_time(s):
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def lookup_npm(name: str, fetch=http_json) -> dict:
    status, doc = fetch("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@").replace("/", "%2f"))
    if status == 404:
        return {"found": False}
    if status != 200 or not isinstance(doc, dict):
        return {"found": None}
    times = doc.get("time") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    vdoc = (doc.get("versions") or {}).get(latest, {}) if latest else {}
    repo = doc.get("repository") or vdoc.get("repository")
    repo = repo.get("url") if isinstance(repo, dict) else repo
    dstatus, dl = fetch("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(name, safe="@"))
    return {
        "found": True,
        "created": times.get("created"),
        "last_release": times.get(latest) if latest else times.get("modified"),
        "weekly_downloads": dl.get("downloads") if dstatus == 200 and isinstance(dl, dict) else None,
        "repository": repo or None,
        "deprecated": bool(vdoc.get("deprecated")),
    }


def lookup_pypi(name: str, fetch=http_json) -> dict:
    status, doc = fetch(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if status == 404:
        return {"found": False}
    if status != 200 or not isinstance(doc, dict):
        return {"found": None}
    info = doc.get("info") or {}
    uploads = [t for files in (doc.get("releases") or {}).values() for f in files if (t := f.get("upload_time_iso_8601"))]
    urls = [u for u in (info.get("project_urls") or {}).values() if u] + [info.get("home_page")]
    repo = next((u for u in urls if u and re.search(r"github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht", u)), None)
    return {
        "found": True,
        "created": min(uploads) if uploads else None,
        "last_release": max(uploads) if uploads else None,
        "weekly_downloads": None,
        "repository": repo,
        "deprecated": "Development Status :: 7 - Inactive" in (info.get("classifiers") or []),
    }


# ---------------------------------------------------------------- judgement

def assess(pkg: dict, meta: dict | None, now: dt.datetime) -> dict:
    """Attach flags to a package. meta is None when no lookup happened (offline / non-registry)."""
    eco, name = pkg["ecosystem"], pkg["name"]
    flags: list[tuple[str, str, str]] = []  # (code, severity, explanation)

    if meta and meta.get("popular"):
        return {**pkg, "lookup": "known-popular", "flags": []}

    if pkg["non_registry"]:
        return {**pkg, "lookup": "skipped", "flags": [("NON_REGISTRY_SOURCE", "low",
                "Installed from a git URL, path or archive, so the registry checks cannot vouch for it. Review it by hand.")]}

    valid = NPM_NAME.match(name) if eco == "npm" else PYPI_NAME.match(name)
    if not valid:
        return {**pkg, "lookup": "skipped", "flags": [("INVALID_NAME", "medium", "Not a legal package name, so it was not looked up.")]}

    target = typosquat_target(eco, name)
    lookup = "offline" if meta is None else ("error" if meta["found"] is None else "ok")

    if meta is not None and meta["found"] is False:
        flags.append(("NOT_FOUND", "high", "Not on the public registry. Either hallucinated, a private package, or a name an attacker can register today."))
    if meta and meta.get("found"):
        created = _parse_time(meta.get("created"))
        last = _parse_time(meta.get("last_release"))
        young = bool(created and (now - created).days < NEW_DAYS)
        few = meta.get("weekly_downloads") is not None and meta["weekly_downloads"] < FEW_DOWNLOADS
        if young:
            flags.append(("NEW_PACKAGE", "medium", f"First published {(now - created).days} days ago."))
        if few:
            flags.append(("FEW_DOWNLOADS", "medium", f"Only {meta['weekly_downloads']} downloads last week."))
        if not meta.get("repository"):
            flags.append(("NO_REPOSITORY", "low", "No source repository is linked, so the published code cannot be compared to source."))
        if meta.get("deprecated"):
            flags.append(("DEPRECATED", "low", "Marked deprecated or inactive by its maintainer."))
        if last and (now - last).days > ABANDONED_YEARS * 365:
            flags.append(("ABANDONED", "low", f"No release since {last.date().isoformat()}."))
        if target:
            sev = "high" if (young or few or meta.get("weekly_downloads") is None) else "medium"
            flags.append(("TYPOSQUAT_SUSPECT", sev, f"Name is one or two edits from the popular package '{target}'. Confirm it is the one you meant."))
    elif target:
        flags.append(("TYPOSQUAT_SUSPECT", "high" if meta is not None and meta["found"] is False else "medium",
                      f"Name is one or two edits from the popular package '{target}'. Confirm it is the one you meant."))

    out = {**pkg, "lookup": lookup}
    if meta and meta.get("found"):
        out["registry"] = {k: meta.get(k) for k in ("created", "last_release", "weekly_downloads", "repository")}
    out["flags"] = flags
    return out


def risk_of(flags) -> str | None:
    if not flags:
        return None
    return max((f[1] for f in flags), key=lambda s: SEVERITY_RANK[s])


def run(root: Path, offline: bool = False, fetch=http_json, now: dt.datetime | None = None, workers: int = 8,
        only: set | None = None) -> dict:
    """Assess every declared package, or just those in `only` (a set of (ecosystem, name))."""
    now = now or dt.datetime.now(dt.timezone.utc)
    pkgs = [p for p in collect(root) if only is None or (p["ecosystem"], p["name"]) in only]

    def work(pkg):
        meta = None
        needs_lookup = not offline and not pkg["non_registry"] and \
            (NPM_NAME if pkg["ecosystem"] == "npm" else PYPI_NAME).match(pkg["name"]) and \
            pkg["name"] not in POPULAR[pkg["ecosystem"]]
        if needs_lookup:
            meta = (lookup_npm if pkg["ecosystem"] == "npm" else lookup_pypi)(pkg["name"], fetch)
        elif pkg["name"] in POPULAR[pkg["ecosystem"]]:
            meta = {"found": True, "popular": True}
        return assess(pkg, meta, now)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        assessed = list(ex.map(work, pkgs))

    packages = []
    for a in assessed:
        flags = [{"code": c, "severity": s, "explanation": e} for c, s, e in a.pop("flags")]
        a["flags"] = flags
        a["risk"] = risk_of([(f["code"], f["severity"]) for f in flags])
        packages.append(a)

    flagged = [p for p in packages if p["flags"]]
    unreachable = [p["name"] for p in packages if p["lookup"] == "error"]
    return {
        "generated": now.date().isoformat(),
        "mode": "offline" if offline else "online",
        "root": str(root),
        "summary": {
            "total": len(packages),
            "looked_up": sum(1 for p in packages if p["lookup"] == "ok"),
            "unreachable": len(unreachable),
            "high": sum(1 for p in packages if p["risk"] == "high"),
            "medium": sum(1 for p in packages if p["risk"] == "medium"),
            "low": sum(1 for p in packages if p["risk"] == "low"),
        },
        "unreachable": unreachable,
        "flagged": sorted(flagged, key=lambda p: -SEVERITY_RANK[p["risk"]]),
        "packages": [{"ecosystem": p["ecosystem"], "name": p["name"], "lookup": p["lookup"], "risk": p["risk"]} for p in packages],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--out", type=Path, help="write JSON here (default: print)")
    ap.add_argument("--offline", action="store_true", help="make no network requests")
    args = ap.parse_args()

    result = run(args.root.resolve(), offline=args.offline)
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    s = result["summary"]
    print(f"{s['total']} packages, {s['high']} high / {s['medium']} medium / {s['low']} low risk, "
          f"{s['unreachable']} unreachable ({result['mode']})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
