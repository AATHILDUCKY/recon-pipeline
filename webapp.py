#!/usr/bin/env python3
"""Authenticated web control plane for the authorized recon pipeline."""
from __future__ import annotations

import atexit
import datetime as dt
import hmac
import html
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, stream_with_context, url_for
from markupsafe import Markup, escape

from recon_pipeline import canonical_domain, canonical_scope_subdomain, redact_url, scope_entry_host

BASE_DIR = Path(__file__).resolve().parent
ACTIVE_STATUSES = ("queued", "running")
STATUS_PRIORITY = {"running": 0, "queued": 1, "failed": 2, "complete": 3, "cancelled": 4, "": 5}
TARGET_WITH_LATEST_SQL = """SELECT t.*,p.name project_name,s.id scan_id,s.profile,s.status,s.created_at scan_created,
              s.started_at,s.finished_at,s.error FROM targets t LEFT JOIN projects p ON p.id=t.project_id
              LEFT JOIN scans s ON s.id=(SELECT id FROM scans WHERE target_id=t.id ORDER BY id DESC LIMIT 1)"""


def load_env(path: Path) -> None:
    """Load a small dotenv file without making application startup a dependency."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            os.environ.setdefault(key, value)


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


SCAN_STAGE_CHOICES = (
    ("subdomain_enum", "Subdomain enum"),
    ("dns", "DNS"),
    ("http", "HTTP probe"),
    ("ports", "Ports"),
    ("content", "Content"),
    ("technologies", "Tech"),
    ("secrets", "Secrets"),
    ("tls", "TLS"),
    ("active_checks", "Active checks"),
    ("vulnerabilities", "Findings"),
)


def scope_upload_dir(app: Flask) -> Path:
    path = Path(app.config["SCOPE_UPLOAD_DIR"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def scope_upload_path(app: Flask, upload_id: str) -> Path | None:
    if not re.fullmatch(r"[a-f0-9]{32}", upload_id or ""):
        return None
    path = (scope_upload_dir(app) / f"{upload_id}.txt").resolve()
    try:
        path.relative_to(scope_upload_dir(app).resolve())
    except ValueError:
        return None
    return path


def read_scope_upload(app: Flask, upload_id: str) -> str:
    path = scope_upload_path(app, upload_id)
    if not path or not path.is_file():
        return ""
    if path.stat().st_size > app.config["MAX_SCOPE_UPLOAD_BYTES"]:
        raise ValueError("Scope list is too large for one submission.")
    return path.read_text(encoding="utf-8", errors="replace")


def scope_entries(raw_scope: str) -> list[str]:
    return [value.strip() for value in re.split(r"[\s,]+", raw_scope) if value.strip()]


def selected_scan_options(form: Any, domain: str, raw_scope: str | None = None) -> tuple[str, str]:
    enabled=set(form.getlist("stages")) if hasattr(form,"getlist") else set()
    if not enabled and str(form.get("stage_policy","")) != "1":
        enabled={key for key,_ in SCAN_STAGE_CHOICES}
    valid={key for key,_ in SCAN_STAGE_CHOICES}
    skip_stages=sorted(valid-enabled)
    raw_scope=str(form.get("scope_subdomains","") if raw_scope is None else raw_scope)
    subdomains=[]
    invalid=[]
    for value in scope_entries(raw_scope):
        try:subdomains.append(canonical_scope_subdomain(value,domain))
        except ValueError:invalid.append(value[:80])
    if invalid:
        raise ValueError(f"Invalid/out-of-scope subdomain(s): {', '.join(invalid[:5])}")
    return ",".join(skip_stages), "\n".join(dict.fromkeys(subdomains))


def scope_only_targets(raw_scope: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Turn an exact host list into independent scoped scans."""
    targets: list[tuple[str, str]] = []
    invalid: list[str] = []
    for value in scope_entries(raw_scope):
        host = scope_entry_host(value)
        host = host.split("*", 1)[0] if "*" in host else host
        host = host.strip(".")
        try:
            domain = canonical_domain(host if host else value)
            scoped = canonical_scope_subdomain(value, domain)
        except ValueError:
            invalid.append(value[:80]); continue
        if "*" in scoped:
            invalid.append(value[:80]); continue
        targets.append((domain, scoped))
    deduped = list(dict.fromkeys(targets))
    return deduped, invalid


def project_name(value: str, fallback: str = "Deep analysis") -> str:
    name = re.sub(r"\s+", " ", str(value or "").strip())
    return (name or fallback)[:120]


def scan_activity_value(row: dict[str, Any]) -> str:
    return str(row.get("finished_at") or row.get("started_at") or row.get("scan_created") or row.get("created_at") or "")


def status_priority(status: Any) -> int:
    return STATUS_PRIORITY.get(str(status or ""), STATUS_PRIORITY[""])


def connect_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect_db(path) as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS projects (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS targets (
          id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE,
          project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
          request_rate INTEGER NOT NULL DEFAULT 30 CHECK(request_rate BETWEEN 1 AND 500),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
          profile TEXT NOT NULL CHECK(profile IN ('passive','standard','deep')),
          request_rate INTEGER CHECK(request_rate BETWEEN 1 AND 500),
          skip_stages TEXT,
          scope_subdomains TEXT,
          status TEXT NOT NULL CHECK(status IN ('queued','running','complete','failed','cancelled')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, started_at TEXT, finished_at TEXT,
          result_dir TEXT, log_path TEXT, exit_code INTEGER, error TEXT
        );
        CREATE INDEX IF NOT EXISTS scans_target_created ON scans(target_id, id DESC);
        CREATE INDEX IF NOT EXISTS scans_status_created ON scans(status, id);
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(targets)")}
        if "project_id" not in columns:
            db.execute("ALTER TABLE targets ADD COLUMN project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL")
        if "request_rate" not in columns:
            db.execute("ALTER TABLE targets ADD COLUMN request_rate INTEGER NOT NULL DEFAULT 30")
        db.execute("INSERT OR IGNORE INTO projects(name) VALUES('Deep analysis')")
        default_project = db.execute("SELECT id FROM projects WHERE name='Deep analysis'").fetchone()["id"]
        for row in db.execute("SELECT id,domain FROM targets WHERE project_id IS NULL").fetchall():
            db.execute("INSERT OR IGNORE INTO projects(name) VALUES(?)", (row["domain"],))
            project = db.execute("SELECT id FROM projects WHERE name=?", (row["domain"],)).fetchone()
            db.execute("UPDATE targets SET project_id=? WHERE id=?", ((project["id"] if project else default_project), row["id"]))
        scan_columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)")}
        if "request_rate" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN request_rate INTEGER")
        if "skip_stages" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN skip_stages TEXT")
        if "scope_subdomains" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN scope_subdomains TEXT")


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def safe_next(value: str | None) -> str:
    return value if value and value.startswith("/") and not value.startswith("//") else url_for("dashboard")


def tail_text(path: Path, lines: int = 80, max_bytes: int = 64_000) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read().decode("utf-8", "replace")
        return "\n".join(data.splitlines()[-lines:])
    except OSError:
        return ""


def result_database(app: Flask, stored_dir: str | None) -> Path | None:
    if not stored_dir:
        return None
    root = Path(app.config["RESULTS_DIR"]).resolve()
    candidate = (Path(stored_dir) / "recon.sqlite3").resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def scoped_path(candidate: str | None, root: str) -> Path | None:
    """Return a stored artifact path only when it is inside its configured root."""
    if not candidate:
        return None
    path, boundary = Path(candidate).resolve(), Path(root).resolve()
    try:
        relative = path.relative_to(boundary)
    except ValueError:
        return None
    return path if relative.parts else None


def scoped_child(root: str, *parts: str) -> Path:
    path = (Path(root).resolve().joinpath(*parts)).resolve()
    path.relative_to(Path(root).resolve())
    return path


def scan_artifact_paths(app: Flask, scans: list[sqlite3.Row]) -> list[Path]:
    paths: list[Path] = []
    for scan in scans:
        result_path = scoped_path(scan["result_dir"] if "result_dir" in scan.keys() else None, app.config["RESULTS_DIR"])
        log_path = scoped_path(scan["log_path"] if "log_path" in scan.keys() else None, app.config["LOG_DIR"])
        if result_path:
            paths.append(result_path)
        if log_path:
            paths.append(log_path)
    return paths


def cleanup_paths(paths: list[Path]) -> bool:
    ok = True
    for path in sorted(set(paths), key=lambda item: len(item.parts), reverse=True):
        try:
            if path.is_dir():
                shutil.rmtree(path)
            elif path.is_file():
                path.unlink()
        except OSError:
            ok = False
    return ok


def result_inventory(app: Flask, stored_dir: str | None) -> dict[str, set[str]]:
    """Read stable identifiers used to compare consecutive completed scans."""
    db_path = result_database(app, stored_dir)
    inventory = {"subdomains": set(), "endpoints": set(), "services": set()}
    if not db_path:
        return inventory
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        run = db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if run:
            inventory["subdomains"] = {r[0] for r in db.execute("SELECT hostname FROM assets WHERE run_id=?", (run[0],)) if r[0]}
            inventory["endpoints"] = {redact_url(r[0]) for r in db.execute("SELECT url FROM endpoints WHERE run_id=?", (run[0],)) if r[0]}
            inventory["services"] = {redact_url(r[0]) for r in db.execute("SELECT url FROM http_services WHERE run_id=?", (run[0],)) if r[0]}
        db.close()
    except sqlite3.Error:
        pass
    return inventory


def scan_result_dir(app: Flask, scan: sqlite3.Row | dict[str, Any]) -> str | None:
    stored = (scan.get("result_dir") if isinstance(scan, dict) else (scan["result_dir"] if "result_dir" in scan.keys() else None)) or None
    if stored:
        return stored
    target_id, scan_id = scan["target_id"], scan["id"]
    root = Path(app.config["RESULTS_DIR"]) / f"target-{target_id}" / f"scan-{scan_id}"
    databases = sorted(root.glob("*/recon.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
    return str(databases[0].parent) if databases else None


def progress_summary(app: Flask, scan: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    stored_dir = scan_result_dir(app, scan)
    data = read_results(app, stored_dir) if stored_dir else {"counts": {}, "tools": []}
    tools = data.get("tools", [])
    failures = [row for row in tools if row.get("status") in {"failed", "timeout"}]
    skipped = [row for row in tools if row.get("status") == "skipped"]
    counts = data.get("counts", {})
    return {
        "counts": {"subdomains": counts.get("Assets", 0), "services": counts.get("Web services", 0), "endpoints": counts.get("Endpoints", 0), "findings": counts.get("Findings", 0), "ports": counts.get("Ports", 0)},
        "failures": failures[-8:],
        "skipped": len(skipped),
        "result_dir": stored_dir,
    }


TECH_METADATA = {"country", "email", "html5", "httpserver", "ip", "passwordfield", "script", "title", "uncommonheaders"}
TECH_CATEGORY_RULES = (
    ("CMS & commerce", ("wordpress", "drupal", "joomla", "shopify", "magento", "woocommerce", "ghost", "contentful")),
    ("Frameworks", ("react", "next.js", "nextjs", "vue", "nuxt", "angular", "svelte", "django", "flask", "laravel", "rails", "spring", "asp.net", "express")),
    ("Languages & runtimes", ("php", "python", "ruby", "java", "node.js", "nodejs", "perl", "go:")),
    ("Servers & proxies", ("nginx", "apache", "iis", "caddy", "tomcat", "envoy", "haproxy", "openresty", "gunicorn")),
    ("JavaScript libraries", ("jquery", "bootstrap", "lodash", "webpack", "requirejs", "modernizr", "alpine.js", "htmx")),
    ("CDN, analytics & security", ("cdn:", "waf:", "google analytics", "gtm", "segment", "akamai", "fastly", "imperva", "sucuri")),
)


def technology_category(label: str) -> str:
    low=label.lower()
    for category,needles in TECH_CATEGORY_RULES:
        if any(needle in low for needle in needles):return category
    return "Other detected technologies"


def parse_technologies(value: Any, server: str = "") -> list[str]:
    """Normalize HTTPX/WhatWeb technology JSON while suppressing metadata plugins."""
    raw=value
    if isinstance(value,str):
        try:raw=json.loads(value)
        except json.JSONDecodeError:raw=[value]
    if isinstance(raw,dict):raw=list(raw)
    if not isinstance(raw,list):raw=[]
    found=[]
    for item in raw:
        label=str(item).strip().strip("[]\"'")
        name=label.split(":",1)[0].strip().lower()
        if label and name not in TECH_METADATA:found.append(label)
    server_label=str(server or "").strip();server_product=re.split(r"[/:\s]",server_label.lower(),maxsplit=1)[0]
    if server_label and not any(re.split(r"[/:\s]",item.lower(),maxsplit=1)[0]==server_product for item in found):
        found.append(server_label)
    return sorted(set(found),key=str.lower)


def technology_version(label: str) -> str:
    match=re.search(r"(?:[:/]\s*|\bv)(\d+(?:[._-]\d+)*(?:[a-z0-9._-]*))",label,re.I)
    return match.group(1) if match else ""


def project_summaries(db: sqlite3.Connection, project_id: int | None = None) -> list[dict[str, Any]]:
    db.execute("INSERT OR IGNORE INTO projects(name) VALUES('Deep analysis')")
    default_project = db.execute("SELECT id FROM projects WHERE name='Deep analysis'").fetchone()["id"]
    db.execute("UPDATE targets SET project_id=? WHERE project_id IS NULL", (default_project,))
    where = "WHERE p.id=?" if project_id else ""
    args = (project_id,) if project_id else ()
    projects = [dict(row) for row in db.execute(f"SELECT p.* FROM projects p {where} ORDER BY p.id DESC", args)]
    for project in projects:
        targets = [dict(row) for row in db.execute(TARGET_WITH_LATEST_SQL + " WHERE t.project_id=? ORDER BY t.domain", (project["id"],))]
        targets.sort(key=lambda row: (status_priority(row.get("status")), -int(row.get("scan_id") or 0), str(row.get("domain") or "").lower()))
        statuses = [row.get("status") for row in targets if row.get("status")]
        latest_activity = max((scan_activity_value(row) for row in targets), default="")
        project.update({
            "targets": targets,
            "domain_count": len(targets),
            "scan_count": sum(1 for row in targets if row.get("scan_id")),
            "active_count": sum(1 for row in targets if row.get("status") in ACTIVE_STATUSES),
            "latest_activity": latest_activity,
            "status": "running" if "running" in statuses else ("queued" if "queued" in statuses else (statuses[0] if statuses else "")),
        })
    projects.sort(key=lambda row: str(row.get("name") or "").lower())
    projects.sort(key=lambda row: str(row.get("latest_activity") or row.get("created_at") or ""), reverse=True)
    projects.sort(key=lambda row: -(row.get("active_count") or 0))
    projects.sort(key=lambda row: status_priority(row.get("status")))
    return projects


def relevant_technology_findings(label: str, findings: list[dict[str,Any]]) -> list[dict[str,Any]]:
    product=re.split(r"[/:\s]",label.lower(),maxsplit=1)[0]
    if len(product)<3:return []
    pattern=re.compile(r"(?<![a-z0-9])"+re.escape(product)+r"(?![a-z0-9])",re.I)
    return [item for item in findings if pattern.search(" ".join(str(item.get(key) or "") for key in ("name","template_id","source")))]


def build_technology_inventory(services: list[dict[str,Any]], findings: list[dict[str,Any]] | None = None, technology_rows: list[dict[str,Any]] | None = None) -> tuple[list[dict[str,Any]],list[dict[str,Any]],dict[str,int]]:
    findings=findings or [];findings_by_host:dict[str,list[dict[str,Any]]]={}
    technology_rows=technology_rows or []
    for item in findings:
        host=str(item.get("host") or "")
        if host:findings_by_host.setdefault(host,[]).append(item)
    hosts:dict[str,dict[str,Any]]={};counts:dict[str,int]={}
    for service in services:
        host=str(service.get("host") or "")
        if not host:continue
        technologies=parse_technologies(service.get("technologies"),str(service.get("server") or ""))
        service["technology_list"]=technologies;service["technologies_display"]=" · ".join(technologies)
        entry=hosts.setdefault(host,{"host":host,"services":[],"technologies":set()})
        entry["services"].append(service);entry["technologies"].update(technologies)
    tech_details:dict[tuple[str,str],dict[str,Any]]={}
    for row in technology_rows:
        host=str(row.get("host") or "")
        if not host:continue
        label=str(row.get("name") or "").strip()
        version=str(row.get("version") or "").strip()
        if version:label=f"{label}:{version}"
        if not label:continue
        entry=hosts.setdefault(host,{"host":host,"services":[],"technologies":set()})
        entry["technologies"].add(label)
        tech_details[(host,label.lower())]=row
    result=[]
    for host,entry in sorted(hosts.items()):
        categories:dict[str,list[dict[str,Any]]]={};host_findings=findings_by_host.get(host,[]);assessments=[]
        for label in sorted(entry["technologies"],key=str.lower):
            matches=relevant_technology_findings(label,host_findings);version=technology_version(label)
            detail=tech_details.get((host,label.lower()),{})
            assessment={"name":label,"version":version,"status":"matched" if matches else ("versioned" if version else "unknown"),"findings":matches,"source":detail.get("source",""),"confidence":detail.get("confidence",""),"evidence":detail.get("evidence","")}
            categories.setdefault(technology_category(label),[]).append(assessment);assessments.append(assessment);counts[label]=counts.get(label,0)+1
        security_findings=[item for item in host_findings if str(item.get("severity") or "").lower() in {"critical","high","medium"} or re.search(r"CVE-\d{4}-\d+",str(item.get("template_id") or item.get("name") or ""),re.I)]
        cves=sorted({cve.upper() for item in security_findings for cve in re.findall(r"CVE-\d{4}-\d+"," ".join(str(item.get(key) or "") for key in ("template_id","name")),flags=re.I)})
        result.append({"host":host,"services":entry["services"],"technologies":sorted(entry["technologies"],key=str.lower),"categories":categories,"assessments":assessments,"security_findings":security_findings,"cves":cves})
    summary=[{"name":name,"hosts":count,"category":technology_category(name)} for name,count in sorted(counts.items(),key=lambda item:(-item[1],item[0].lower()))]
    metrics={"hosts":len(result),"fingerprinted_hosts":sum(bool(item["technologies"]) for item in result),"technologies":len(counts),"services":len(services),"versioned":sum(bool(item["version"]) for host in result for item in host["assessments"]),"security_matches":sum(bool(host["security_findings"]) for host in result)}
    return result,summary,metrics


def build_ip_inventory(ports: list[dict[str,Any]], dns: list[dict[str,Any]]) -> tuple[list[dict[str,Any]],dict[str,int]]:
    addresses:dict[str,dict[str,Any]]={}
    for row in dns:
        if str(row.get("type") or "") not in {"A","AAAA"}:continue
        ip=str(row.get("value") or "")
        if ip:addresses.setdefault(ip,{"ip":ip,"hostnames":set(),"ports":[]})["hostnames"].add(str(row.get("hostname") or ""))
    for row in ports:
        ip=str(row.get("ip") or "")
        if not ip:continue
        entry=addresses.setdefault(ip,{"ip":ip,"hostnames":set(),"ports":[]});entry["hostnames"].add(str(row.get("hostname") or ""))
        scripts=row.get("scripts")
        if isinstance(scripts,str):
            try:scripts=json.loads(scripts or "{}")
            except json.JSONDecodeError:scripts={}
        row["script_list"]=[{"id":str(key),"output":str(value)} for key,value in (scripts.items() if isinstance(scripts,dict) else [])]
        cpe=row.get("cpe")
        if isinstance(cpe,str):
            try:cpe=json.loads(cpe or "[]")
            except json.JSONDecodeError:cpe=[cpe] if cpe else []
        row["cpe_list"]=cpe if isinstance(cpe,list) else []
        identity=(row.get("port"),row.get("protocol"),row.get("hostname"))
        if not any((item.get("port"),item.get("protocol"),item.get("hostname"))==identity for item in entry["ports"]):entry["ports"].append(row)
    result=[]
    for ip,entry in sorted(addresses.items(),key=lambda item:(":" in item[0],item[0])):
        entry["hostnames"]=sorted(name for name in entry["hostnames"] if name);entry["ports"].sort(key=lambda row:(int(row.get("port") or 0),str(row.get("hostname") or "")))
        result.append(entry)
    metrics={"addresses":len(result),"ipv4":sum(":" not in item["ip"] for item in result),"ipv6":sum(":" in item["ip"] for item in result),"open_ports":len({(item["ip"],port.get("port"),port.get("protocol")) for item in result for port in item["ports"]}),"services":len({(item["ip"],port.get("port"),port.get("protocol")) for item in result for port in item["ports"] if port.get("product") or port.get("service")})}
    return result,metrics


def read_results(app: Flask, stored_dir: str | None, previous_dir: str | None = None) -> dict[str, Any]:
    db_path = result_database(app, stored_dir)
    empty = {"counts": {}, "active_subdomains": 0, "services": [], "technologies": [], "tech_stacks": [], "technology_summary": [], "technology_metrics": {"hosts":0,"fingerprinted_hosts":0,"technologies":0,"services":0,"versioned":0,"security_matches":0}, "ports": [], "ip_inventory": [], "ip_metrics": {"addresses":0,"ipv4":0,"ipv6":0,"open_ports":0,"services":0}, "dns": [], "findings": [],
             "endpoints": [], "subdomains": [], "repositories": [], "tools": [], "domain_info": [], "inputs": [], "encoded": [],
             "new_counts": {"subdomains": 0, "endpoints": 0, "services": 0}, "has_baseline": bool(previous_dir)}
    if not db_path:
        return empty
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        run = db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if not run:
            db.close(); return empty
        run_id = run["id"]
        available_tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        tables = {"Assets": "assets", "DNS": "dns_records", "Ports": "ports", "Web services": "http_services",
                  "Endpoints": "endpoints", "Findings": "findings", "Repositories": "repositories", "Inputs": "input_points", "Encoded values": "encoded_artifacts"}
        if "technologies" in available_tables:tables["Technologies"]="technologies"
        data = dict(empty)
        data["counts"] = {label: db.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (run_id,)).fetchone()[0]
                          for label, table in tables.items()}
        port_columns={row[1] for row in db.execute("PRAGMA table_info(ports)")}
        port_fields=[field if field in port_columns else f"NULL AS {field}" for field in ("hostname","ip","port","protocol","service","state","reason","product","version","extra_info","cpe","scripts","source")]
        asset_columns={row[1] for row in db.execute("PRAGMA table_info(assets)")}
        asset_fields=[field if field in asset_columns else f"NULL AS {field}" for field in ("hostname","source","resolved","http_active","active_url","http_status","first_seen")]
        queries = {
            "services": "SELECT url,host,status,title,server,technologies,content_type,ip FROM http_services WHERE run_id=? ORDER BY host,status,url LIMIT 1000",
            "subdomains": f"SELECT {','.join(asset_fields)} FROM assets WHERE run_id=? ORDER BY hostname LIMIT 5000",
            "ports": f"SELECT {','.join(port_fields)} FROM ports WHERE run_id=? ORDER BY ip,port,hostname LIMIT 5000",
            "dns": "SELECT hostname,type,value,source FROM dns_records WHERE run_id=? ORDER BY hostname,type LIMIT 500",
            "findings": "SELECT severity,name,template_id,matched_at,host,tool AS source FROM findings WHERE run_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT 500",
            "endpoints": "SELECT url,source,extension,query_keys FROM endpoints WHERE run_id=? ORDER BY id DESC LIMIT 1000",
            "repositories": "SELECT url,source,scanned FROM repositories WHERE run_id=? ORDER BY url LIMIT 200",
            "tools": "SELECT tool,stage,status,duration,exit_code FROM tool_runs WHERE run_id=? ORDER BY id LIMIT 500",
            "domain_info": "SELECT key,value,source FROM domain_info WHERE run_id=? ORDER BY key LIMIT 500",
            "inputs": "SELECT page_url,action_url,method,name,input_type,tested,reflection_context FROM input_points WHERE run_id=? ORDER BY page_url,name LIMIT 500",
            "encoded": "SELECT source_url,location,kind,value_preview,decoded_preview,is_hash,analyzer FROM encoded_artifacts WHERE run_id=? ORDER BY source_url,location LIMIT 500",
        }
        if "technologies" in available_tables:
            queries["technologies"]="SELECT host,url,name,version,category,source,confidence,evidence FROM technologies WHERE run_id=? ORDER BY host,category,name,version LIMIT 2000"
        for name, query in queries.items():
            rows = [dict(row) for row in db.execute(query, (run_id,)).fetchall()]
            for row in rows:
                for key in ("url", "matched_at"):
                    if row.get(key): row[key] = redact_url(str(row[key]))
            data[name] = rows
        data["tech_stacks"],data["technology_summary"],data["technology_metrics"]=build_technology_inventory(data["services"],data["findings"],data["technologies"])
        data["ip_inventory"],data["ip_metrics"]=build_ip_inventory(data["ports"],data["dns"])
        data["active_subdomains"]=sum(bool(row.get("http_active")) for row in data["subdomains"])
        previous = result_inventory(app, previous_dir)
        for collection, key in (("subdomains", "hostname"), ("endpoints", "url"), ("services", "url")):
            for row in data[collection]:
                row["is_new"] = bool(previous_dir and row.get(key) not in previous[collection])
        data["new_counts"] = {name: sum(bool(row.get("is_new")) for row in data[name])
                              for name in ("subdomains", "endpoints", "services")}
        db.close()
        return data
    except sqlite3.Error:
        return empty


REPORT_SECTIONS = (
    ("Assets", "assets", "hostname,source,resolved,first_seen", "hostname"),
    ("Domain information", "domain_info", "key,value,source", "key,value"),
    ("DNS records", "dns_records", "hostname,type,value,source", "hostname,type,value"),
    ("Open ports", "ports", "hostname,ip,port,protocol,service,source", "hostname,port"),
    ("Web services", "http_services", "url,host,status,title,server,technologies,content_type,content_length,ip,final_url", "host,url"),
    ("Technology versions", "technologies", "host,url,name,version,category,source,confidence,evidence", "host,category,name,version"),
    ("Scanner observations", "findings", "severity,name,template_id,matched_at,host,tool,evidence", "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,name"),
    ("Discovered endpoints", "endpoints", "url,host,path,query_keys,extension,source,first_seen", "host,path,url"),
    ("Input surface", "input_points", "page_url,action_url,method,name,input_type,tested,reflection_context", "page_url,name"),
    ("Encoded and hashed values", "encoded_artifacts", "source_url,location,kind,value_preview,decoded_preview,is_hash,analyzer", "source_url,location"),
    ("Discovered repositories", "repositories", "url,host,source,scanned", "url"),
    ("Tool execution ledger", "tool_runs", "stage,tool,started_at,duration,exit_code,status", "id"),
)

REPORT_URL_FIELDS = {"url", "final_url", "matched_at", "page_url", "action_url", "source_url"}
REPORT_BOOLEAN_FIELDS = {"resolved", "tested", "is_hash", "scanned"}


def markdown_cell(value: Any, field: str = "") -> str:
    """Render one safe, single-line Markdown table cell."""
    if value is None or value == "":
        return "—"
    if field in REPORT_BOOLEAN_FIELDS:
        return "yes" if bool(value) else "no"
    text = redact_url(str(value)) if field in REPORT_URL_FIELDS else str(value)
    text = html.escape(text, quote=False)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def markdown_table(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return "_No data collected._\n"
    fields = list(rows[0].keys())
    labels = [field.replace("_", " ").title() for field in fields]
    lines = ["| " + " | ".join(labels) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    lines.extend("| " + " | ".join(markdown_cell(row[field], field) for field in fields) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def build_markdown_report(app: Flask, stored_dir: str | None, scan: sqlite3.Row, domain: str, project: str = "") -> str | None:
    """Build a complete, portable report from a completed scan database."""
    db_path = result_database(app, stored_dir)
    if not db_path:
        return None
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        db.row_factory = sqlite3.Row
        run = db.execute("SELECT id,domain,profile,started_at,finished_at,status FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if not run:
            db.close()
            return None
        collected = []
        available_tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for title, table, columns, order in REPORT_SECTIONS:
            if table not in available_tables:
                continue
            rows = db.execute(f"SELECT {columns} FROM {table} WHERE run_id=? ORDER BY {order}", (run["id"],)).fetchall()
            collected.append((title, rows))
        db.close()
    except sqlite3.Error:
        return None

    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# Reconnaissance report: {project or domain}", "",
        "> Authorized attack-surface inventory. Automated observations require manual validation.", "",
        "## Scan details", "",
        f"- **Project:** {markdown_cell(project or '—')}", f"- **Scope item:** {markdown_cell(domain)}", f"- **Scan ID:** {scan['id']}",
        f"- **Profile:** {markdown_cell(run['profile'])}", f"- **Status:** {markdown_cell(run['status'])}",
        f"- **Started:** {markdown_cell(run['started_at'])}",
        f"- **Finished:** {markdown_cell(run['finished_at'] or scan['finished_at'])}",
        f"- **Report generated:** {generated}", "", "## Summary", "",
        "| Category | Count |", "| --- | ---: |",
    ]
    lines.extend(f"| {title} | {len(rows)} |" for title, rows in collected)
    for title, rows in collected:
        lines.extend(["", f"## {title}", "", markdown_table(rows).rstrip()])
    lines.extend(["", "---", "", "Sensitive URL query values are redacted. Raw evidence remains in the protected scan workspace.", ""])
    return "\n".join(lines)


class ScanWorker:
    def __init__(self, app: Flask):
        self.app = app
        self.stop_event = threading.Event()
        self.process: subprocess.Popen[str] | None = None
        self.current_scan_id: int | None = None
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, name="recon-worker", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.cancel_current()

    def cancel_current(self, scan_ids: set[int] | None = None) -> bool:
        with self.lock:
            process = self.process
            current_scan_id = self.current_scan_id
            if not process or process.poll() is not None:
                return False
            if scan_ids is not None and current_scan_id not in scan_ids:
                return False
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                process.terminate()
            return True

    def claim(self) -> sqlite3.Row | None:
        with connect_db(Path(self.app.config["CONTROL_DB"])) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT s.*,t.domain,COALESCE(s.request_rate,t.request_rate) AS effective_rate FROM scans s JOIN targets t ON t.id=s.target_id
                              WHERE s.status='queued' ORDER BY s.id LIMIT 1""").fetchone()
            if row:
                db.execute("UPDATE scans SET status='running',started_at=CURRENT_TIMESTAMP,error=NULL WHERE id=?", (row["id"],))
            db.commit()
            return row

    def command(self, row: sqlite3.Row, output: Path) -> list[str]:
        cfg = self.app.config
        command = [sys.executable, str(BASE_DIR / "recon_pipeline.py"), row["domain"],
                "--i-have-authorization", "--profile", row["profile"], "--output", str(output),
                "--rate", str(row["effective_rate"] or cfg["SCAN_RATE"]), "--concurrency", str(cfg["SCAN_CONCURRENCY"]),
                "--active-delay", str(cfg["SCAN_ACTIVE_DELAY"])]
        if row["skip_stages"]:
            command += ["--skip-stages", row["skip_stages"]]
        if row["scope_subdomains"]:
            scope_file = output / "scope-subdomains.txt"
            scope_file.parent.mkdir(parents=True, exist_ok=True)
            scope_file.write_text(str(row["scope_subdomains"]), encoding="utf-8")
            command += ["--scope-subdomains-file", str(scope_file)]
        user_agent_file = BASE_DIR / "user-agent.txt"
        if user_agent_file.is_file():
            command += ["--user-agent-file", str(user_agent_file)]
        return command

    def execute(self, row: sqlite3.Row) -> None:
        output = Path(self.app.config["RESULTS_DIR"]) / f"target-{row['target_id']}" / f"scan-{row['id']}"
        log_path = Path(self.app.config["LOG_DIR"]) / f"scan-{row['id']}.log"
        output.mkdir(parents=True, exist_ok=True); log_path.parent.mkdir(parents=True, exist_ok=True)
        with connect_db(Path(self.app.config["CONTROL_DB"])) as db:
            db.execute("UPDATE scans SET log_path=? WHERE id=?", (str(log_path), row["id"]))
        child_env = os.environ.copy()
        child_env.pop("ADMIN_PASSWORD", None); child_env.pop("FLASK_SECRET_KEY", None)
        exit_code = -1; error = None
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as log:
                process = subprocess.Popen(self.command(row, output), cwd=BASE_DIR, stdout=log,
                                           stderr=subprocess.STDOUT, text=True, env=child_env, start_new_session=True)
                with self.lock:
                    self.process = process
                    self.current_scan_id = int(row["id"])
                while process.poll() is None and not self.stop_event.wait(0.5):
                    pass
                if process.poll() is None:
                    self.cancel_current({int(row["id"])})
                try:
                    exit_code = process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        process.kill()
                    exit_code = process.wait(timeout=5)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            with self.lock:
                self.process = None
                self.current_scan_id = None
        databases = sorted(output.glob("*/recon.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
        result_dir = str(databases[0].parent) if databases else None
        with connect_db(Path(self.app.config["CONTROL_DB"])) as db:
            current = db.execute("SELECT status FROM scans WHERE id=?", (row["id"],)).fetchone()
        cancelled = bool(current and current["status"] == "cancelled")
        status = "cancelled" if cancelled else ("complete" if exit_code == 0 and result_dir else "failed")
        if status == "failed" and not error:
            error = f"scanner exited with code {exit_code}" if exit_code != 0 else "scanner produced no result database"
        with connect_db(Path(self.app.config["CONTROL_DB"])) as db:
            db.execute("""UPDATE scans SET status=?,finished_at=CURRENT_TIMESTAMP,result_dir=?,exit_code=?,error=? WHERE id=?""",
                       (status, result_dir, exit_code, error, row["id"]))

    def run(self) -> None:
        while not self.stop_event.is_set():
            row = self.claim()
            if row: self.execute(row)
            else: self.stop_event.wait(1)


def create_app(config: dict[str, Any] | None = None, *, start_worker: bool = True) -> Flask:
    load_env(BASE_DIR / ".env")
    app = Flask(__name__)
    instance = BASE_DIR / "instance"
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "change-this-development-secret"),
        ADMIN_USERNAME=os.getenv("ADMIN_USERNAME", "admin"), ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD", "change-me-now"),
        CONTROL_DB=str(instance / "control.sqlite3"), LOG_DIR=str(instance / "logs"),
        RESULTS_DIR=str((BASE_DIR / os.getenv("RESULTS_DIR", "results/web")).resolve()),
        DEFAULT_SCAN_PROFILE=os.getenv("DEFAULT_SCAN_PROFILE", "standard"),
        SCAN_RATE=int(os.getenv("SCAN_RATE", "30")), SCAN_CONCURRENCY=int(os.getenv("SCAN_CONCURRENCY", "15")),
        SCAN_ACTIVE_DELAY=float(os.getenv("SCAN_ACTIVE_DELAY", "1.0")),
        SCOPE_UPLOAD_DIR=str(instance / "scope-uploads"), MAX_SCOPE_UPLOAD_BYTES=10 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=truthy(os.getenv("SESSION_COOKIE_SECURE", "false")),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=64 * 1024,
    )
    if config: app.config.update(config)
    init_db(Path(app.config["CONTROL_DB"]))
    Path(app.config["RESULTS_DIR"]).mkdir(parents=True, exist_ok=True)

    @app.before_request
    def csrf_guard() -> None:
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        token = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if request.method == "POST" and not hmac.compare_digest(session["csrf_token"], token):
            abort(400, "Invalid or missing CSRF token")

    @app.context_processor
    def template_context() -> dict[str, Any]:
        labels = {"url":"URL", "status":"Status", "title":"Title", "server":"Server", "technologies":"Technologies",
                  "key":"Field", "value":"Value", "source":"Source", "hostname":"Host", "ip":"IP", "port":"Port",
                  "protocol":"Protocol", "service":"Service", "type":"Type", "severity":"Severity", "name":"Name",
                  "template_id":"Template", "matched_at":"Matched at", "tool":"Tool", "stage":"Stage",
                  "duration":"Seconds", "exit_code":"Exit"}
        def table(_name: str, rows: list[dict[str, Any]]) -> Markup:
            if not rows: return Markup('<div class="empty">No data collected.</div>')
            keys = list(rows[0].keys())
            head = "".join(f"<th>{escape(labels.get(key, key.replace('_',' ').title()))}</th>" for key in keys)
            body = "".join("<tr>" + "".join(f"<td>{escape('—' if row.get(key) is None else row.get(key))}</td>" for key in keys) + "</tr>" for row in rows)
            return Markup(f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')
        return {"csrf_token": session.get("csrf_token", ""), "default_profile": app.config["DEFAULT_SCAN_PROFILE"], "scan_stage_choices": SCAN_STAGE_CHOICES, "table": table}

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            valid = hmac.compare_digest(username, str(app.config["ADMIN_USERNAME"])) and hmac.compare_digest(password, str(app.config["ADMIN_PASSWORD"]))
            if valid:
                session.clear(); session["authenticated"] = True; session["csrf_token"] = secrets.token_urlsafe(32); session.permanent = True
                return redirect(safe_next(request.form.get("next")))
            time.sleep(0.25); flash("Invalid username or password.", "error")
        return render_template("login.html", next=safe_next(request.args.get("next")))

    @app.post("/logout")
    @login_required
    def logout() -> Any:
        session.clear(); return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard() -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            projects = project_summaries(db)
            totals = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM scans GROUP BY status")}
        return render_template("dashboard.html", projects=projects, totals=totals)

    @app.get("/targets")
    @login_required
    def targets_index() -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            projects = project_summaries(db)
        return render_template("targets.html", projects=projects)

    @app.get("/projects/<int:project_id>")
    @login_required
    def project_detail(project_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            projects = project_summaries(db, project_id)
            if not projects: abort(404)
            project = projects[0]
            scans = db.execute("""SELECT s.*,t.domain,COALESCE(s.request_rate,t.request_rate) AS effective_rate FROM scans s JOIN targets t ON t.id=s.target_id
                                WHERE t.project_id=? ORDER BY CASE s.status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,s.id DESC LIMIT 300""",
                               (project_id,)).fetchall()
        return render_template("project.html", project=project, scans=scans)

    @app.post("/projects/<int:project_id>/stop")
    @login_required
    def stop_project(project_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
                abort(404)
            active = db.execute("""SELECT s.id FROM scans s JOIN targets t ON t.id=s.target_id
                                WHERE t.project_id=? AND s.status IN ('queued','running')""", (project_id,)).fetchall()
            scan_ids = {int(row["id"]) for row in active}
            if scan_ids:
                placeholders = ",".join("?" for _ in scan_ids)
                db.execute(f"""UPDATE scans SET status='cancelled',finished_at=CURRENT_TIMESTAMP,
                           error='Cancelled by project stop request' WHERE id IN ({placeholders})""", tuple(scan_ids))
        worker = app.extensions.get("scan_worker")
        if worker and scan_ids:
            worker.cancel_current(scan_ids)
        flash(f"Stopped {len(scan_ids)} active scan(s)." if scan_ids else "No active scans were running for this project.", "info")
        return redirect(url_for("project_detail", project_id=project_id))

    @app.post("/projects/<int:project_id>/delete")
    @login_required
    def delete_project(project_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            project = db.execute("SELECT id,name FROM projects WHERE id=?", (project_id,)).fetchone()
            if not project:
                abort(404)
            scans = db.execute("""SELECT s.id,s.status,s.result_dir,s.log_path FROM scans s JOIN targets t ON t.id=s.target_id
                                WHERE t.project_id=?""", (project_id,)).fetchall()
            targets = db.execute("SELECT id FROM targets WHERE project_id=?", (project_id,)).fetchall()
            scan_ids = {int(row["id"]) for row in scans}
            active_ids = {int(row["id"]) for row in scans if row["status"] in ACTIVE_STATUSES}
            artifact_paths = scan_artifact_paths(app, scans)
            for target in targets:
                artifact_paths.append(scoped_child(app.config["RESULTS_DIR"], f"target-{target['id']}"))
            if active_ids:
                placeholders = ",".join("?" for _ in active_ids)
                db.execute(f"""UPDATE scans SET status='cancelled',finished_at=CURRENT_TIMESTAMP,
                           error='Cancelled by project delete request' WHERE id IN ({placeholders})""", tuple(active_ids))
            db.execute("DELETE FROM targets WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM projects WHERE id=?", (project_id,))
        worker = app.extensions.get("scan_worker")
        if worker and active_ids:
            worker.cancel_current(active_ids)
        cleaned = cleanup_paths(artifact_paths)
        if cleaned:
            flash(f"Project {project['name']} was deleted with {len(scan_ids)} scan record(s) and result folders.", "success")
        else:
            flash(f"Project {project['name']} was deleted, but one or more artifacts could not be removed.", "info")
        return redirect(url_for("dashboard"))

    @app.get("/scans")
    @login_required
    def scan_activity() -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scans = db.execute("""SELECT s.*,t.domain,p.name project_name,COALESCE(s.request_rate,t.request_rate) AS effective_rate FROM scans s JOIN targets t ON t.id=s.target_id LEFT JOIN projects p ON p.id=t.project_id
                                ORDER BY CASE s.status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,s.id DESC LIMIT 300""").fetchall()
            totals = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM scans GROUP BY status")}
        return render_template("scans.html", scans=scans, totals=totals)

    @app.get("/attack-surface")
    @login_required
    def attack_surface() -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            snapshots = db.execute("""SELECT s.*,t.domain,p.name project_name FROM scans s JOIN targets t ON t.id=s.target_id LEFT JOIN projects p ON p.id=t.project_id
              WHERE s.status='complete' AND s.id=(SELECT id FROM scans WHERE target_id=t.id AND status='complete' ORDER BY id DESC LIMIT 1)
              ORDER BY s.finished_at DESC""").fetchall()
            prepared = []
            for scan in snapshots:
                previous = db.execute("SELECT result_dir FROM scans WHERE target_id=? AND status='complete' AND id<? ORDER BY id DESC LIMIT 1",
                                      (scan["target_id"], scan["id"])).fetchone()
                results = read_results(app, scan["result_dir"], previous["result_dir"] if previous else None)
                prepared.append((scan, results))
        totals = {"subdomains": 0, "services": 0, "endpoints": 0, "findings": 0, "ports": 0}
        changes: list[dict[str, Any]] = []
        targets = []
        for scan, results in prepared:
            summary = {"scan": scan, "counts": results["counts"], "new_counts": results["new_counts"]}
            targets.append(summary)
            totals["subdomains"] += results["counts"].get("Assets", 0)
            totals["services"] += results["counts"].get("Web services", 0)
            totals["endpoints"] += results["counts"].get("Endpoints", 0)
            totals["findings"] += results["counts"].get("Findings", 0)
            totals["ports"] += results["counts"].get("Ports", 0)
            for kind, field in (("Subdomain", "subdomains"), ("Endpoint", "endpoints"), ("Web service", "services")):
                key = "hostname" if field == "subdomains" else "url"
                for row in results[field]:
                    if row.get("is_new"):
                        changes.append({"kind": kind, "value": row.get(key), "domain": scan["domain"], "project": scan["project_name"] or scan["domain"],
                                        "target_id": scan["target_id"], "scan_id": scan["id"]})
        return render_template("attack_surface.html", totals=totals, targets=targets, changes=changes[:100])

    @app.get("/reports")
    @login_required
    def reports() -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scans = db.execute("""SELECT s.*,t.domain,p.name project_name FROM scans s JOIN targets t ON t.id=s.target_id LEFT JOIN projects p ON p.id=t.project_id
                                WHERE s.status='complete' ORDER BY s.id DESC LIMIT 300""").fetchall()
        return render_template("reports.html", scans=scans)

    @app.get("/reports/<int:scan_id>")
    @login_required
    def scan_report(scan_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scan = db.execute("SELECT s.*,t.domain,p.name project_name,COALESCE(s.request_rate,t.request_rate) AS effective_rate FROM scans s JOIN targets t ON t.id=s.target_id LEFT JOIN projects p ON p.id=t.project_id WHERE s.id=? AND s.status='complete'", (scan_id,)).fetchone()
            if not scan: abort(404)
            previous = db.execute("SELECT result_dir FROM scans WHERE target_id=? AND status='complete' AND id<? ORDER BY id DESC LIMIT 1",
                                  (scan["target_id"], scan["id"])).fetchone()
        results = read_results(app, scan["result_dir"], previous["result_dir"] if previous else None)
        return render_template("scan_report.html", scan=scan, results=results)

    @app.get("/reports/<int:scan_id>/report.md")
    @login_required
    def download_scan_markdown(scan_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scan = db.execute("SELECT s.*,t.domain,p.name project_name FROM scans s JOIN targets t ON t.id=s.target_id LEFT JOIN projects p ON p.id=t.project_id WHERE s.id=? AND s.status='complete'", (scan_id,)).fetchone()
        if not scan: abort(404)
        report = build_markdown_report(app, scan["result_dir"], scan, scan["domain"], scan["project_name"] if "project_name" in scan.keys() else "")
        if report is None: abort(404, "Completed scan results are unavailable")
        response = Response(report, content_type="text/markdown; charset=utf-8")
        response.headers["Content-Disposition"] = f'attachment; filename="{scan["domain"]}-recon-scan-{scan["id"]}.md"'
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.post("/targets")
    @login_required
    def add_targets() -> Any:
        if request.form.get("authorized") != "yes":
            flash("Confirm written authorization before scheduling a scan.", "error"); return redirect(url_for("dashboard"))
        raw = request.form.get("targets", "")
        name = project_name(request.form.get("project_name", ""))
        scope_upload_id = request.form.get("scope_upload_id", "")
        try:
            raw_scope = read_scope_upload(app, scope_upload_id) if scope_upload_id else str(request.form.get("scope_subdomains", ""))
        except ValueError as exc:
            flash(str(exc), "error"); return redirect(url_for("dashboard"))
        profile = request.form.get("profile", app.config["DEFAULT_SCAN_PROFILE"])
        if profile not in {"passive", "standard", "deep"}: abort(400)
        try:
            request_rate = int(request.form.get("request_rate", app.config["SCAN_RATE"]))
        except ValueError:
            abort(400, "Request rate must be a number")
        if not 1 <= request_rate <= 500:
            abort(400, "Request rate must be between 1 and 500")
        values = [x.strip() for x in re.split(r"[\s,]+", raw) if x.strip()]
        domains, invalid = [], []
        for value in values[:200]:
            try: domains.append(canonical_domain(value))
            except ValueError: invalid.append(value[:80])
        domains = list(dict.fromkeys(domains))
        queued = 0
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            if domains:
                db.execute("INSERT OR IGNORE INTO projects(name) VALUES(?)", (name,))
                project_id = db.execute("SELECT id FROM projects WHERE name=?", (name,)).fetchone()["id"]
                for domain in domains:
                    try:
                        skip_stages, scope_subdomains = selected_scan_options(request.form, domain, raw_scope)
                    except ValueError as exc:
                        flash(str(exc), "error")
                        continue
                    db.execute("INSERT OR IGNORE INTO targets(domain,project_id,request_rate) VALUES(?,?,?)", (domain, project_id, request_rate))
                    db.execute("UPDATE targets SET project_id=?,request_rate=? WHERE domain=?", (project_id, request_rate, domain))
                    target_id = db.execute("SELECT id FROM targets WHERE domain=?", (domain,)).fetchone()["id"]
                    active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('queued','running')", (target_id,)).fetchone()
                    if not active:
                        db.execute("INSERT INTO scans(target_id,profile,request_rate,skip_stages,scope_subdomains,status) VALUES(?,?,?,?,?,'queued')", (target_id, profile, request_rate, skip_stages, scope_subdomains)); queued += 1
            elif raw_scope.strip():
                db.execute("INSERT OR IGNORE INTO projects(name) VALUES(?)", (name,))
                project_id = db.execute("SELECT id FROM projects WHERE name=?", (name,)).fetchone()["id"]
                skip_stages, _ = selected_scan_options(request.form, "example.com", "")
                scoped_targets, scope_invalid = scope_only_targets(raw_scope)
                invalid.extend(scope_invalid)
                for domain, scope_subdomains in scoped_targets[:5000]:
                    db.execute("INSERT OR IGNORE INTO targets(domain,project_id,request_rate) VALUES(?,?,?)", (domain, project_id, request_rate))
                    db.execute("UPDATE targets SET project_id=?,request_rate=? WHERE domain=?", (project_id, request_rate, domain))
                    target_id = db.execute("SELECT id FROM targets WHERE domain=?", (domain,)).fetchone()["id"]
                    active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('queued','running')", (target_id,)).fetchone()
                    if not active:
                        db.execute("INSERT INTO scans(target_id,profile,request_rate,skip_stages,scope_subdomains,status) VALUES(?,?,?,?,?,'queued')", (target_id, profile, request_rate, skip_stages, scope_subdomains)); queued += 1
                if len(scoped_targets) > 5000:
                    flash("Queued the first 5000 scoped hosts; submit the remaining hosts as another batch.", "info")
        upload_path = scope_upload_path(app, scope_upload_id) if scope_upload_id else None
        if upload_path and upload_path.is_file():
            try: upload_path.unlink()
            except OSError: pass
        if queued: flash(f"Queued {queued} scan(s) for {name}.", "success")
        if invalid: flash(f"Skipped {len(invalid)} invalid target(s).", "error")
        if not queued and not invalid: flash("No new scans were queued; provide domains or exact scoped hosts, or these targets may already be active.", "info")
        return redirect(url_for("dashboard"))

    @app.post("/api/scope-upload")
    @login_required
    def scope_upload() -> Any:
        upload_id = request.form.get("upload_id") or secrets.token_hex(16)
        path = scope_upload_path(app, upload_id)
        if not path: abort(400, "Invalid upload id")
        chunk = request.form.get("chunk", "")
        if not chunk: abort(400, "Empty upload chunk")
        if len(chunk.encode("utf-8", "replace")) > 48 * 1024:
            abort(413, "Upload chunk is too large")
        mode = "ab" if path.exists() else "wb"
        with path.open(mode) as handle:
            handle.write(chunk.encode("utf-8", "replace"))
        if path.stat().st_size > app.config["MAX_SCOPE_UPLOAD_BYTES"]:
            try: path.unlink()
            except OSError: pass
            abort(413, "Scope list is too large")
        return jsonify(upload_id=upload_id, bytes=path.stat().st_size)

    @app.get("/targets/<int:target_id>")
    @login_required
    def target_detail(target_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            target = db.execute("SELECT t.*,p.name project_name FROM targets t LEFT JOIN projects p ON p.id=t.project_id WHERE t.id=?", (target_id,)).fetchone()
            if not target: abort(404)
            scans = db.execute("SELECT * FROM scans WHERE target_id=? ORDER BY id DESC LIMIT 30", (target_id,)).fetchall()
            active_scan = db.execute("SELECT * FROM scans WHERE target_id=? AND status IN ('queued','running') ORDER BY id LIMIT 1", (target_id,)).fetchone()
            latest_complete = db.execute("SELECT * FROM scans WHERE target_id=? AND status='complete' ORDER BY id DESC LIMIT 1", (target_id,)).fetchone()
            previous_complete = None
            if latest_complete:
                previous_complete = db.execute("SELECT * FROM scans WHERE target_id=? AND status='complete' AND id<? ORDER BY id DESC LIMIT 1", (target_id, latest_complete["id"])).fetchone()
        results = read_results(app, latest_complete["result_dir"] if latest_complete else None,
                               previous_complete["result_dir"] if previous_complete else None)
        return render_template("target.html", target=target, scans=scans, active_scan=active_scan, latest_complete=latest_complete, results=results)

    @app.post("/targets/<int:target_id>/settings")
    @login_required
    def target_settings(target_id: int) -> Any:
        try:
            request_rate = int(request.form.get("request_rate", ""))
        except ValueError:
            abort(400, "Request rate must be a number")
        if not 1 <= request_rate <= 500:
            abort(400, "Request rate must be between 1 and 500")
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            if not db.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone(): abort(404)
            db.execute("UPDATE targets SET request_rate=? WHERE id=?", (request_rate, target_id))
        flash(f"Rate limit updated to {request_rate} requests per second.", "success")
        return redirect(url_for("target_detail", target_id=target_id))

    @app.get("/targets/<int:target_id>/report.md")
    @login_required
    def download_markdown_report(target_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            target = db.execute("SELECT t.*,p.name project_name FROM targets t LEFT JOIN projects p ON p.id=t.project_id WHERE t.id=?", (target_id,)).fetchone()
            if not target:
                abort(404)
            scan = db.execute("SELECT * FROM scans WHERE target_id=? AND status='complete' ORDER BY id DESC LIMIT 1", (target_id,)).fetchone()
        if not scan:
            abort(404, "No completed scan is available")
        report = build_markdown_report(app, scan["result_dir"], scan, target["domain"], target["project_name"] if "project_name" in target.keys() else "")
        if report is None:
            abort(404, "Completed scan results are unavailable")
        response = Response(report, content_type="text/markdown; charset=utf-8")
        response.headers["Content-Disposition"] = f'attachment; filename="{target["domain"]}-recon-scan-{scan["id"]}.md"'
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.post("/targets/<int:target_id>/scan")
    @login_required
    def rescan(target_id: int) -> Any:
        if request.form.get("authorized") != "yes": abort(400, "Authorization confirmation required")
        profile = request.form.get("profile", app.config["DEFAULT_SCAN_PROFILE"])
        if profile not in {"passive", "standard", "deep"}: abort(400)
        try:
            request_rate = int(request.form.get("request_rate", app.config["SCAN_RATE"]))
        except ValueError:
            abort(400, "Request rate must be a number")
        if not 1 <= request_rate <= 500:
            abort(400, "Request rate must be between 1 and 500")
        scope_upload_id = request.form.get("scope_upload_id", "")
        try:
            raw_scope = read_scope_upload(app, scope_upload_id) if scope_upload_id else str(request.form.get("scope_subdomains", ""))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("target_detail", target_id=target_id))
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            target = db.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if not target: abort(404)
            try:
                skip_stages, scope_subdomains = selected_scan_options(request.form, str(target["domain"]), raw_scope)
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("target_detail", target_id=target_id))
            active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('queued','running')", (target_id,)).fetchone()
            if active: flash("This target already has an active scan.", "info")
            else:
                db.execute("UPDATE targets SET request_rate=? WHERE id=?", (request_rate, target_id))
                db.execute("INSERT INTO scans(target_id,profile,request_rate,skip_stages,scope_subdomains,status) VALUES(?,?,?,?,?,'queued')", (target_id, profile, request_rate, skip_stages, scope_subdomains))
                flash(f"Scan queued at {request_rate} requests per second.", "success")
        upload_path = scope_upload_path(app, scope_upload_id) if scope_upload_id else None
        if upload_path and upload_path.is_file():
            try: upload_path.unlink()
            except OSError: pass
        return redirect(url_for("target_detail", target_id=target_id))

    @app.post("/scans/<int:scan_id>/delete")
    @login_required
    def delete_scan(scan_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scan = db.execute("SELECT id,target_id,status,result_dir,log_path FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not scan: abort(404)
            if scan["status"] == "running":
                flash("A running scan cannot be deleted. Wait for it to finish before removing it.", "error")
                return redirect(safe_next(request.form.get("next")))
            artifact_paths = scan_artifact_paths(app, [scan])
            db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        if not cleanup_paths(artifact_paths):
            flash(f"Scan #{scan_id} was removed, but one artifact could not be cleaned up.", "info")
        else:
            flash(f"Scan #{scan_id} and its stored artifacts were deleted.", "success")
        return redirect(safe_next(request.form.get("next")))

    @app.get("/api/scans/<int:scan_id>")
    @login_required
    def scan_status(scan_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scan = db.execute("SELECT id,target_id,status,profile,started_at,finished_at,result_dir,log_path,error,exit_code FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan: abort(404)
        payload = dict(scan); log_path = payload.pop("log_path", None)
        payload["log"] = tail_text(Path(log_path)) if log_path else ""
        payload["progress"] = progress_summary(app, scan)
        return jsonify(payload)

    @app.get("/api/events")
    @login_required
    def live_events() -> Response:
        """Push workspace changes over one long-lived connection."""
        tracked_scan = request.args.get("scan_id", type=int)

        @stream_with_context
        def generate() -> Any:
            previous = ""
            heartbeat_at = time.monotonic()
            while True:
                with connect_db(Path(app.config["CONTROL_DB"])) as db:
                    totals = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM scans GROUP BY status")}
                    latest = [dict(row) for row in db.execute("""SELECT s.id,s.target_id,t.project_id,s.status,s.profile,s.request_rate,s.created_at,s.started_at,s.finished_at,s.error
                      FROM scans s JOIN targets t ON t.id=s.target_id WHERE s.id=(SELECT id FROM scans WHERE target_id=s.target_id ORDER BY id DESC LIMIT 1) ORDER BY s.id DESC""")]
                    tracked = None
                    if tracked_scan:
                        row = db.execute("SELECT id,target_id,status,profile,request_rate,started_at,finished_at,result_dir,log_path,error,exit_code FROM scans WHERE id=?", (tracked_scan,)).fetchone()
                        if row:
                            tracked = dict(row)
                            log_path = tracked.pop("log_path", None)
                            tracked["log"] = tail_text(Path(log_path)) if log_path else ""
                            tracked["progress"] = progress_summary(app, row)
                payload = json.dumps({"totals": totals, "latest": latest, "tracked": tracked}, sort_keys=True, separators=(",", ":"))
                if payload != previous:
                    yield f"event: workspace\ndata: {payload}\n\n"
                    previous = payload
                    heartbeat_at = time.monotonic()
                elif time.monotonic() - heartbeat_at >= 15:
                    yield ": keep-alive\n\n"
                    heartbeat_at = time.monotonic()
                time.sleep(1)

        response = Response(generate(), mimetype="text/event-stream")
        response.headers["Cache-Control"] = "no-cache, no-transform"
        response.headers["X-Accel-Buffering"] = "no"
        return response

    @app.get("/healthz")
    def health() -> Any: return jsonify(status="ok")

    if start_worker and not app.config.get("TESTING"):
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            db.execute("UPDATE scans SET status='failed',finished_at=CURRENT_TIMESTAMP,error='Web service restarted during scan' WHERE status='running'")
        worker = ScanWorker(app); worker.start(); app.extensions["scan_worker"] = worker; atexit.register(worker.stop)
    return app


app = create_app(start_worker=False)

if __name__ == "__main__":
    app = create_app(start_worker=True)
    app.run(host=os.getenv("WEB_HOST", "127.0.0.1"), port=int(os.getenv("WEB_PORT", "8080")), debug=False, use_reloader=False)
