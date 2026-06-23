#!/usr/bin/env python3
"""Authenticated web control plane for the authorized recon pipeline."""
from __future__ import annotations

import atexit
import datetime as dt
import hmac
import html
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape

from recon_pipeline import canonical_domain, redact_url

BASE_DIR = Path(__file__).resolve().parent
ACTIVE_STATUSES = ("queued", "running")


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
        CREATE TABLE IF NOT EXISTS targets (
          id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
          profile TEXT NOT NULL CHECK(profile IN ('passive','standard','deep')),
          status TEXT NOT NULL CHECK(status IN ('queued','running','complete','failed','cancelled')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, started_at TEXT, finished_at TEXT,
          result_dir TEXT, log_path TEXT, exit_code INTEGER, error TEXT
        );
        CREATE INDEX IF NOT EXISTS scans_target_created ON scans(target_id, id DESC);
        CREATE INDEX IF NOT EXISTS scans_status_created ON scans(status, id);
        """)


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


def read_results(app: Flask, stored_dir: str | None) -> dict[str, Any]:
    db_path = result_database(app, stored_dir)
    empty = {"counts": {}, "services": [], "ports": [], "dns": [], "findings": [],
             "endpoints": [], "repositories": [], "tools": [], "domain_info": [], "inputs": [], "encoded": []}
    if not db_path:
        return empty
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        run = db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if not run:
            db.close(); return empty
        run_id = run["id"]
        tables = {"Assets": "assets", "DNS": "dns_records", "Ports": "ports", "Web services": "http_services",
                  "Endpoints": "endpoints", "Findings": "findings", "Repositories": "repositories", "Inputs": "input_points", "Encoded values": "encoded_artifacts"}
        data = dict(empty)
        data["counts"] = {label: db.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (run_id,)).fetchone()[0]
                          for label, table in tables.items()}
        queries = {
            "services": "SELECT url,status,title,server,technologies FROM http_services WHERE run_id=? ORDER BY status,url LIMIT 300",
            "ports": "SELECT hostname,ip,port,protocol,service FROM ports WHERE run_id=? ORDER BY hostname,port LIMIT 500",
            "dns": "SELECT hostname,type,value,source FROM dns_records WHERE run_id=? ORDER BY hostname,type LIMIT 500",
            "findings": "SELECT severity,name,template_id,matched_at,tool AS source FROM findings WHERE run_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT 500",
            "endpoints": "SELECT url,source,extension,query_keys FROM endpoints WHERE run_id=? ORDER BY id DESC LIMIT 1000",
            "repositories": "SELECT url,source,scanned FROM repositories WHERE run_id=? ORDER BY url LIMIT 200",
            "tools": "SELECT tool,stage,status,duration,exit_code FROM tool_runs WHERE run_id=? ORDER BY id LIMIT 500",
            "domain_info": "SELECT key,value,source FROM domain_info WHERE run_id=? ORDER BY key LIMIT 500",
            "inputs": "SELECT page_url,action_url,method,name,input_type,tested,reflection_context FROM input_points WHERE run_id=? ORDER BY page_url,name LIMIT 500",
            "encoded": "SELECT source_url,location,kind,value_preview,decoded_preview,is_hash,analyzer FROM encoded_artifacts WHERE run_id=? ORDER BY source_url,location LIMIT 500",
        }
        for name, query in queries.items():
            rows = [dict(row) for row in db.execute(query, (run_id,)).fetchall()]
            for row in rows:
                for key in ("url", "matched_at"):
                    if row.get(key): row[key] = redact_url(str(row[key]))
            data[name] = rows
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


def build_markdown_report(app: Flask, stored_dir: str | None, scan: sqlite3.Row, domain: str) -> str | None:
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
        for title, table, columns, order in REPORT_SECTIONS:
            rows = db.execute(f"SELECT {columns} FROM {table} WHERE run_id=? ORDER BY {order}", (run["id"],)).fetchall()
            collected.append((title, rows))
        db.close()
    except sqlite3.Error:
        return None

    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# Reconnaissance report: {domain}", "",
        "> Authorized attack-surface inventory. Automated observations require manual validation.", "",
        "## Scan details", "",
        f"- **Target:** {markdown_cell(domain)}", f"- **Scan ID:** {scan['id']}",
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
        self.thread = threading.Thread(target=self.run, name="recon-worker", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def claim(self) -> sqlite3.Row | None:
        with connect_db(Path(self.app.config["CONTROL_DB"])) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT s.*,t.domain FROM scans s JOIN targets t ON t.id=s.target_id
                              WHERE s.status='queued' ORDER BY s.id LIMIT 1""").fetchone()
            if row:
                db.execute("UPDATE scans SET status='running',started_at=CURRENT_TIMESTAMP,error=NULL WHERE id=?", (row["id"],))
            db.commit()
            return row

    def command(self, row: sqlite3.Row, output: Path) -> list[str]:
        cfg = self.app.config
        return [sys.executable, str(BASE_DIR / "recon_pipeline.py"), row["domain"],
                "--i-have-authorization", "--profile", row["profile"], "--output", str(output),
                "--rate", str(cfg["SCAN_RATE"]), "--concurrency", str(cfg["SCAN_CONCURRENCY"]),
                "--active-delay", str(cfg["SCAN_ACTIVE_DELAY"])]

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
                self.process = subprocess.Popen(self.command(row, output), cwd=BASE_DIR, stdout=log,
                                                stderr=subprocess.STDOUT, text=True, env=child_env, start_new_session=True)
                while self.process.poll() is None and not self.stop_event.wait(0.5): pass
                if self.process.poll() is None:
                    self.process.terminate()
                exit_code = self.process.wait(timeout=15)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            self.process = None
        databases = sorted(output.glob("*/recon.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
        result_dir = str(databases[0].parent) if databases else None
        status = "complete" if exit_code == 0 and result_dir else "failed"
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
        if request.method == "POST" and not hmac.compare_digest(session["csrf_token"], request.form.get("csrf_token", "")):
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
        return {"csrf_token": session.get("csrf_token", ""), "default_profile": app.config["DEFAULT_SCAN_PROFILE"], "table": table}

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
            targets = db.execute("""SELECT t.*,s.id scan_id,s.profile,s.status,s.created_at scan_created,
              s.started_at,s.finished_at,s.error FROM targets t LEFT JOIN scans s ON s.id=(SELECT id FROM scans WHERE target_id=t.id ORDER BY id DESC LIMIT 1)
              ORDER BY t.id DESC""").fetchall()
            totals = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM scans GROUP BY status")}
        return render_template("dashboard.html", targets=targets, totals=totals)

    @app.post("/targets")
    @login_required
    def add_targets() -> Any:
        if request.form.get("authorized") != "yes":
            flash("Confirm written authorization before scheduling a scan.", "error"); return redirect(url_for("dashboard"))
        raw = request.form.get("targets", "")
        profile = request.form.get("profile", app.config["DEFAULT_SCAN_PROFILE"])
        if profile not in {"passive", "standard", "deep"}: abort(400)
        values = [x.strip() for x in re.split(r"[\s,]+", raw) if x.strip()]
        domains, invalid = [], []
        for value in values[:200]:
            try: domains.append(canonical_domain(value))
            except ValueError: invalid.append(value[:80])
        domains = list(dict.fromkeys(domains))
        queued = 0
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            for domain in domains:
                db.execute("INSERT OR IGNORE INTO targets(domain) VALUES(?)", (domain,))
                target_id = db.execute("SELECT id FROM targets WHERE domain=?", (domain,)).fetchone()["id"]
                active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('queued','running')", (target_id,)).fetchone()
                if not active:
                    db.execute("INSERT INTO scans(target_id,profile,status) VALUES(?,?,'queued')", (target_id, profile)); queued += 1
        if queued: flash(f"Queued {queued} authorized target scan(s).", "success")
        if invalid: flash(f"Skipped {len(invalid)} invalid target(s).", "error")
        if not queued and not invalid: flash("No new scans were queued; these targets may already be active.", "info")
        return redirect(url_for("dashboard"))

    @app.get("/targets/<int:target_id>")
    @login_required
    def target_detail(target_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            target = db.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if not target: abort(404)
            scans = db.execute("SELECT * FROM scans WHERE target_id=? ORDER BY id DESC LIMIT 30", (target_id,)).fetchall()
            active_scan = db.execute("SELECT * FROM scans WHERE target_id=? AND status IN ('queued','running') ORDER BY id LIMIT 1", (target_id,)).fetchone()
            latest_complete = db.execute("SELECT * FROM scans WHERE target_id=? AND status='complete' ORDER BY id DESC LIMIT 1", (target_id,)).fetchone()
        results = read_results(app, latest_complete["result_dir"] if latest_complete else None)
        return render_template("target.html", target=target, scans=scans, active_scan=active_scan, latest_complete=latest_complete, results=results)

    @app.get("/targets/<int:target_id>/report.md")
    @login_required
    def download_markdown_report(target_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            target = db.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if not target:
                abort(404)
            scan = db.execute("SELECT * FROM scans WHERE target_id=? AND status='complete' ORDER BY id DESC LIMIT 1", (target_id,)).fetchone()
        if not scan:
            abort(404, "No completed scan is available")
        report = build_markdown_report(app, scan["result_dir"], scan, target["domain"])
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
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            if not db.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone(): abort(404)
            active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('queued','running')", (target_id,)).fetchone()
            if active: flash("This target already has an active scan.", "info")
            else: db.execute("INSERT INTO scans(target_id,profile,status) VALUES(?,?,'queued')", (target_id, profile)); flash("Scan queued.", "success")
        return redirect(url_for("target_detail", target_id=target_id))

    @app.get("/api/scans/<int:scan_id>")
    @login_required
    def scan_status(scan_id: int) -> Any:
        with connect_db(Path(app.config["CONTROL_DB"])) as db:
            scan = db.execute("SELECT id,target_id,status,profile,started_at,finished_at,log_path,error,exit_code FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan: abort(404)
        payload = dict(scan); log_path = payload.pop("log_path", None)
        payload["log"] = tail_text(Path(log_path)) if log_path else ""
        return jsonify(payload)

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
