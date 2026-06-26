#!/usr/bin/env python3
"""Authorized, scope-safe reconnaissance pipeline using installed CLI tools.

The orchestrator deliberately does not exploit targets. It inventories DNS, ports,
HTTP services, URLs, technologies and scanner observations, preserving raw output.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import dataclasses
import datetime as dt
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import math
import os
import random
import re
import shutil
import signal
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import ssl
import xml.etree.ElementTree as ET
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable

VERSION = "2.0.0"
FFUF_VALID_STATUSES = frozenset((*range(200, 300), 301, 302, 307, 308, 401, 403, 405))
WHATWEB_METADATA_PLUGINS = {"country","email","html5","httpserver","ip","passwordfield","script","title","uncommonheaders"}
DOMAIN_RE = re.compile(r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
VERSION_RE = re.compile(r"(?<![A-Za-z0-9])v?(\d+(?:[._-]\d+){0,5}(?:[a-z0-9._+-]*))", re.I)
SECRET_QUERY_KEYS = {"access_token", "api_key", "apikey", "auth", "authorization", "client_secret", "key", "password", "secret", "sig", "signature", "token"}
SKIP_FETCH_EXTENSIONS = {"7z","avi","avif","bmp","css","eot","flac","gif","gz","ico","jpeg","jpg","m4a","mov","mp3","mp4","mpeg","otf","pdf","png","rar","svg","tar","ttf","wav","webm","webp","woff","woff2","zip"}
ANSI = {"cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m", "dim": "\033[2m", "reset": "\033[0m"}
WAPITI_BASE_MODULES = {"wapp", "cms", "methods"}
WAPITI_PARAMETER_MODULES = {"xss", "permanentxss", "sql", "timesql", "file", "exec", "redirect", "crlf", "ldap"}
WAPITI_BODY_MODULES = {"xxe"}
WAPITI_UPLOAD_MODULES = {"upload"}
WAPITI_TECH_MODULES = {"log4shell", "spring4shell"}
WAPITI_LEVELS = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
TECH_CATEGORY_RULES = (
    ("CMS & commerce", ("wordpress", "drupal", "joomla", "shopify", "magento", "woocommerce", "ghost", "contentful", "strapi", "sanity", "directus")),
    ("Frameworks", ("react", "next.js", "nextjs", "vue", "nuxt", "angular", "svelte", "django", "flask", "laravel", "rails", "spring", "asp.net", "express")),
    ("Languages & runtimes", ("php", "python", "ruby", "java", "node.js", "nodejs", "perl", "go", "openjdk")),
    ("Servers & proxies", ("nginx", "apache", "httpd", "iis", "caddy", "tomcat", "envoy", "haproxy", "openresty", "gunicorn")),
    ("Operating systems", ("ubuntu", "debian", "centos", "red hat", "rhel", "almalinux", "rocky linux", "windows server")),
    ("CDN, analytics & security", ("cdn:", "waf:", "cloudflare", "akamai", "fastly", "imperva", "sucuri")),
)


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def canonical_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if "://" in value or "/" in value or "@" in value:
        raise ValueError("provide an apex domain only, not a URL/path/email")
    try:
        ipaddress.ip_address(value)
        raise ValueError("IP targets are not accepted; provide the authorized apex domain")
    except ValueError as exc:
        if "IP targets" in str(exc):
            raise
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain: {value!r}")
    return value


def in_scope_host(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def scope_entry_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        return (urllib.parse.urlsplit(value).hostname or "").lower().rstrip(".")
    return value.split("/", 1)[0].rstrip(".")


def scope_entry_matches(host: str, entry: str) -> bool:
    host, entry = host.lower().rstrip("."), entry.lower().rstrip(".")
    if entry.startswith("*."):
        suffix = entry[2:]
        return host.endswith("." + suffix) and host != suffix
    if "*" in entry:
        return fnmatchcase(host, entry)
    return host == entry


def host_in_scope_entries(host: str, domain: str, entries: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    if not in_scope_host(host, domain):
        return False
    entries = tuple(entry for entry in entries if entry)
    return any(scope_entry_matches(host, entry) for entry in entries) if entries else True


def canonical_url(value: str, domain: str) -> str | None:
    value = value.strip().rstrip(".,);]")
    try:
        p = urllib.parse.urlsplit(value)
        if p.scheme not in {"http", "https"} or not p.hostname or not in_scope_host(p.hostname, domain):
            return None
        port = p.port
        netloc = p.hostname.lower()
        if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
            netloc += f":{port}"
        path = re.sub(r"/{2,}", "/", p.path or "/")
        query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(p.query, keep_blank_values=True)), doseq=True)
        return urllib.parse.urlunsplit((p.scheme, netloc, path, query, ""))
    except (ValueError, UnicodeError):
        return None


def json_lines(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(errors="replace") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                continue


def clean_version(value: str) -> str:
    value = str(value or "").strip().strip(",:;()[]{}<>\"'")
    if not value:
        return ""
    match = VERSION_RE.search(value)
    return match.group(1).replace("_", ".") if match else ""


def technology_category(name: str) -> str:
    low = str(name or "").lower()
    for category, needles in TECH_CATEGORY_RULES:
        if any(needle in low for needle in needles):
            return category
    return "Other detected technologies"


def technology_label(name: str, version: str = "") -> str:
    name = " ".join(str(name or "").strip().split())
    version = clean_version(version)
    return f"{name}:{version}" if name and version else name


def split_technology_label(label: str) -> tuple[str, str]:
    label = str(label or "").strip()
    if not label:
        return "", ""
    cpe = parse_cpe_technology(label)
    if cpe:
        return cpe
    if ":" in label:
        name, version = label.split(":", 1)
        cleaned = clean_version(version)
        if cleaned:
            return name.strip(), cleaned
    match = re.match(r"(.+?)[/\s]+v?(\d+(?:[._-]\d+)*(?:[a-z0-9._+-]*))$", label, re.I)
    if match:
        return match.group(1).strip(), clean_version(match.group(2))
    return label, ""


def parse_cpe_technology(cpe: str) -> tuple[str, str] | None:
    value = str(cpe or "").strip()
    if not value.startswith("cpe:"):
        return None
    parts = value.split(":")
    if value.startswith("cpe:/") and len(parts) >= 5:
        vendor, product, version = parts[2], parts[3], parts[4]
    elif value.startswith("cpe:2.3:") and len(parts) >= 6:
        vendor, product, version = parts[3], parts[4], parts[5]
    else:
        return None
    product = product.replace("_", " ").strip() or vendor.replace("_", " ").strip()
    version = "" if version in {"*", "-", "ANY"} else clean_version(version)
    return product, version


def parse_server_technology(server: str) -> list[tuple[str, str]]:
    values = []
    for part in re.split(r"\s*,\s*", str(server or "")):
        for token in part.split():
            if not token or token.lower() in {"via", "server"}:
                continue
            if "/" in token:
                name, version = token.split("/", 1)
                if re.search(r"[A-Za-z]", name):
                    values.append((name.strip(), clean_version(version)))
            elif token.lower() in {"nginx", "apache", "cloudflare", "openresty", "caddy"}:
                values.append((token, ""))
    return values


def extract_generator_technologies(text: str) -> list[tuple[str, str, str]]:
    found = []
    for content in re.findall(r"<meta\b[^>]*\bname=[\"']generator[\"'][^>]*\bcontent=[\"']([^\"']+)", text, re.I):
        raw = html.unescape(content)
        for name in ("WordPress", "Drupal", "Joomla", "Ghost", "Magento", "Shopify", "Wix", "Webflow"):
            if re.search(re.escape(name), raw, re.I):
                found.append((name, clean_version(raw), f"meta generator: {raw[:160]}"))
    return found


def extract_body_technologies(url: str, text: str) -> list[tuple[str, str, str]]:
    found = extract_generator_technologies(text)
    low = text.lower()
    if "wp-content/" in low or "wp-includes/" in low:
        versions = re.findall(r"(?:wp-(?:includes|content)|wordpress)[^\"'<>?\s]*[?&]ver=([0-9][A-Za-z0-9._+-]*)", text, re.I)
        found.append(("WordPress", clean_version(versions[0]) if versions else "", "WordPress asset path"))
    if "/_next/static/" in low or '"__next_data__"' in low or "__NEXT_DATA__" in text:
        version = next((clean_version(match) for match in re.findall(r"next(?:\.js)?[@/\s-]+v?([0-9][A-Za-z0-9._+-]*)", text, re.I) if clean_version(match)), "")
        found.append(("Next.js", version, "Next.js runtime markers"))
    react_version = next((clean_version(match) for match in re.findall(r"react(?:\.production\.min)?\.js(?:\?[^\"'<>\s]*ver=|[@/\s-]+v?)([0-9][A-Za-z0-9._+-]*)", text, re.I) if clean_version(match)), "")
    if react_version or any(marker in low for marker in ("data-reactroot", "react-dom", "__react", "react-refresh")):
        found.append(("React", react_version, "React runtime markers"))
    if "drupal-settings-json" in low or "/sites/default/" in low:
        found.append(("Drupal", "", "Drupal page markers"))
    if "joomla" in low or "/media/system/js/" in low:
        found.append(("Joomla", "", "Joomla page markers"))
    if "woocommerce" in low:
        found.append(("WooCommerce", "", "WooCommerce page markers"))
    for package in ("vue", "angular", "svelte", "nuxt", "jquery", "bootstrap", "lodash"):
        pattern = re.compile(rf"{package}(?:\.min)?\.js(?:\?[^\"'<>\s]*ver=|[@/\s-]+v?)([0-9][A-Za-z0-9._+-]*)", re.I)
        version = next((clean_version(match) for match in pattern.findall(text) if clean_version(match)), "")
        if version:
            found.append((package.title() if package != "jquery" else "jQuery", version, f"{package} asset version"))
    return found


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, domain TEXT, profile TEXT, started_at TEXT, finished_at TEXT, status TEXT, config_json TEXT);
        CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, run_id INTEGER, hostname TEXT, source TEXT, resolved INTEGER DEFAULT 0, http_active INTEGER DEFAULT 0, active_url TEXT, http_status INTEGER, first_seen TEXT, UNIQUE(run_id,hostname), FOREIGN KEY(run_id) REFERENCES runs(id));
        CREATE TABLE IF NOT EXISTS dns_records(id INTEGER PRIMARY KEY, run_id INTEGER, hostname TEXT, type TEXT, value TEXT, source TEXT, UNIQUE(run_id,hostname,type,value));
        CREATE TABLE IF NOT EXISTS ports(id INTEGER PRIMARY KEY, run_id INTEGER, hostname TEXT, ip TEXT, port INTEGER, protocol TEXT, service TEXT, state TEXT, reason TEXT, product TEXT, version TEXT, extra_info TEXT, cpe TEXT, scripts TEXT, source TEXT, UNIQUE(run_id,hostname,ip,port,protocol));
        CREATE TABLE IF NOT EXISTS http_services(id INTEGER PRIMARY KEY, run_id INTEGER, url TEXT, host TEXT, status INTEGER, title TEXT, server TEXT, technologies TEXT, content_type TEXT, content_length INTEGER, ip TEXT, final_url TEXT, raw_json TEXT, UNIQUE(run_id,url));
        CREATE TABLE IF NOT EXISTS technologies(id INTEGER PRIMARY KEY, run_id INTEGER, host TEXT, url TEXT, name TEXT, version TEXT, category TEXT, source TEXT, confidence TEXT, evidence TEXT, first_seen TEXT, UNIQUE(run_id,host,url,name,version,source));
        CREATE TABLE IF NOT EXISTS endpoints(id INTEGER PRIMARY KEY, run_id INTEGER, url TEXT, host TEXT, path TEXT, query_keys TEXT, extension TEXT, source TEXT, first_seen TEXT, UNIQUE(run_id,url));
        CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, run_id INTEGER, tool TEXT, severity TEXT, template_id TEXT, name TEXT, matched_at TEXT, host TEXT, evidence TEXT, UNIQUE(run_id,tool,template_id,matched_at));
        CREATE TABLE IF NOT EXISTS domain_info(id INTEGER PRIMARY KEY, run_id INTEGER, key TEXT, value TEXT, source TEXT, UNIQUE(run_id,key,value,source));
        CREATE TABLE IF NOT EXISTS repositories(id INTEGER PRIMARY KEY, run_id INTEGER, url TEXT, host TEXT, source TEXT, scanned INTEGER DEFAULT 0, UNIQUE(run_id,url));
        CREATE TABLE IF NOT EXISTS input_points(id INTEGER PRIMARY KEY, run_id INTEGER, page_url TEXT, action_url TEXT, method TEXT, name TEXT, input_type TEXT, tested INTEGER DEFAULT 0, reflection_context TEXT, UNIQUE(run_id,page_url,action_url,method,name));
        CREATE TABLE IF NOT EXISTS encoded_artifacts(id INTEGER PRIMARY KEY, run_id INTEGER, source_url TEXT, location TEXT, kind TEXT, value_preview TEXT, decoded_preview TEXT, is_hash INTEGER DEFAULT 0, analyzer TEXT, UNIQUE(run_id,source_url,location,kind,value_preview));
        CREATE TABLE IF NOT EXISTS tool_runs(id INTEGER PRIMARY KEY, run_id INTEGER, stage TEXT, tool TEXT, command_json TEXT, started_at TEXT, duration REAL, exit_code INTEGER, status TEXT, stdout_path TEXT, stderr_path TEXT);
        CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(run_id,hostname); CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(run_id,host); CREATE INDEX IF NOT EXISTS idx_technologies_host ON technologies(run_id,host);
        """)
        port_columns={row[1] for row in self.conn.execute("PRAGMA table_info(ports)")}
        for name in ("state","reason","product","version","extra_info","cpe","scripts"):
            if name not in port_columns:self.conn.execute(f"ALTER TABLE ports ADD COLUMN {name} TEXT")
        asset_columns={row[1] for row in self.conn.execute("PRAGMA table_info(assets)")}
        for name,definition in (("http_active","INTEGER DEFAULT 0"),("active_url","TEXT"),("http_status","INTEGER")):
            if name not in asset_columns:self.conn.execute(f"ALTER TABLE assets ADD COLUMN {name} {definition}")
        self.conn.commit()

    def start(self, domain: str, profile: str, config: dict[str, Any]) -> int:
        cur = self.conn.execute("INSERT INTO runs(domain,profile,started_at,status,config_json) VALUES(?,?,?,?,?)", (domain, profile, utcnow(), "running", json.dumps(config, sort_keys=True)))
        self.conn.commit(); return int(cur.lastrowid)

    def execute(self, sql: str, args: tuple[Any, ...] = ()) -> None:
        self.conn.execute(sql, args)

    def values(self, sql: str, args: tuple[Any, ...] = ()) -> list[str]:
        return [str(r[0]) for r in self.conn.execute(sql, args)]

    def finish(self, run_id: int, status: str) -> None:
        self.conn.execute("UPDATE runs SET finished_at=?,status=? WHERE id=?", (utcnow(), status, run_id)); self.conn.commit()


@dataclasses.dataclass
class Config:
    domain: str
    profile: str
    output: Path
    rate: int
    concurrency: int
    timeout: int
    depth: int
    max_urls: int
    wordlist: Path | None
    screenshots: bool
    skip: set[str]
    secret_max_files: int
    secret_max_bytes: int
    active_max_urls: int
    active_delay: float
    repo_max: int
    skip_stages: set[str] = dataclasses.field(default_factory=set)
    scope_subdomains: tuple[str, ...] = ()
    user_agent_file: Path | None = None


STAGE_ALIASES = {
    "subdomains": "subdomain_enum",
    "subdomain-enum": "subdomain_enum",
    "subdomain_enum": "subdomain_enum",
    "dns": "dns",
    "http": "http",
    "ports": "ports",
    "content": "content",
    "technologies": "technologies",
    "secrets": "secrets",
    "tls": "tls",
    "active": "active_checks",
    "active-checks": "active_checks",
    "active_checks": "active_checks",
    "vulnerabilities": "vulnerabilities",
}


def canonical_scope_subdomain(value: str, domain: str) -> str:
    value=scope_entry_host(value)
    if not value:return ""
    validation_host=value.replace("*","a")
    if not in_scope_host(validation_host,domain) or not DOMAIN_RE.fullmatch(validation_host):
        raise ValueError(f"subdomain is outside scope or invalid: {value!r}")
    if "*" in value:
        labels=value.split(".")
        if any("*" in label for label in labels[1:]):
            raise ValueError(f"wildcards are only supported in the left-most label: {value!r}")
        if labels[0] == "*":
            value = "*." + ".".join(labels[1:])
    return value


def parse_stage_skips(value: str) -> set[str]:
    result=set()
    for raw in re.split(r"[\s,]+",value or ""):
        if not raw:continue
        key=raw.strip().lower()
        if key not in STAGE_ALIASES:
            raise ValueError(f"unknown skip stage: {raw}")
        result.add(STAGE_ALIASES[key])
    return result


class UserAgentPool:
    def __init__(self, path: Path | None = None):
        base=Path(__file__).resolve().parent
        candidates=[path] if path else []
        candidates += [base/"user-agent.txt",base/"user-agents.txt"]
        values=[]
        for candidate in candidates:
            if candidate and candidate.is_file():
                values=[line.strip() for line in candidate.read_text(errors="replace").splitlines() if line.strip() and not line.lstrip().startswith("#")]
                if values:break
        self.values=tuple(dict.fromkeys(values)) or (f"ReconPipeline/{VERSION} authorized-security-review",)

    def choose(self, purpose: str = "authorized-security-review") -> str:
        value=random.choice(self.values)
        return value.replace("{purpose}",purpose)


@dataclasses.dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: re.Pattern[str]
    severity: str
    entropy: float = 0.0


SECRET_RULES = (
    SecretRule("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    SecretRule("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b"), "high"),
    SecretRule("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high"),
    SecretRule("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    SecretRule("Google OAuth token", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,300}\b"), "high"),
    SecretRule("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,200}\b"), "high"),
    SecretRule("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{40,200}\b"), "high"),
    SecretRule("GitLab access token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,200}\b"), "high"),
    SecretRule("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,200}\b"), "high"),
    SecretRule("Shopify access token", re.compile(r"\bshpat_[0-9a-fA-F]{32}\b"), "high"),
    SecretRule("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b"), "high"),
    SecretRule("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,128}\b"), "high"),
    SecretRule("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    SecretRule("PyPI upload token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,200}\b"), "high"),
    SecretRule("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "high"),
    SecretRule("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    SecretRule("Mailgun API key", re.compile(r"\bkey-[0-9A-Za-z]{32}\b"), "high"),
    SecretRule("Discord webhook", re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]{10,25}/[A-Za-z0-9_-]{30,200}"), "high"),
    SecretRule("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{30,200}"), "high"),
    SecretRule("Azure SAS token", re.compile(r"(?i)\b(?:SharedAccessSignature\s+)?(?:sv|sig)=[A-Za-z0-9%/+_-]{20,}(?:&[A-Za-z0-9%/+_.=-]+){2,}"), "high"),
    SecretRule("Basic-auth URL", re.compile(r"\bhttps?://[^\s:/@]{2,100}:[^\s/@]{6,200}@[^\s<>\"']+",re.I), "high"),
    SecretRule("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    SecretRule("Database connection string", re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s\"'<>]{8,300}", re.I), "high"),
    SecretRule("Generic secret assignment", re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret)\s*[=:]\s*[\"']([A-Za-z0-9_./+~=-]{16,256})[\"']"), "medium", 3.2),
    SecretRule("Bearer token", re.compile(r"(?i)authorization\s*[=:]\s*[\"']?bearer\s+([A-Za-z0-9_./+~=-]{20,512})"), "medium", 3.2),
)


def shannon_entropy(value: str) -> float:
    if not value:return 0.0
    return -sum((n/len(value))*math.log2(n/len(value)) for n in collections.Counter(value).values())


def redact_secret(value: str) -> str:
    if "PRIVATE KEY" in value:return "-----BEGIN [REDACTED] PRIVATE KEY-----"
    if len(value)<=10:return "[REDACTED]"
    return value[:4]+"…[REDACTED]…"+value[-4:]


def redact_url(value: str) -> str:
    try:
        p=urllib.parse.urlsplit(value); query=[]
        for key,item in urllib.parse.parse_qsl(p.query,keep_blank_values=True):
            query.append((key,"[REDACTED]" if key.lower() in SECRET_QUERY_KEYS else item))
        return urllib.parse.urlunsplit((p.scheme,p.netloc,p.path,urllib.parse.urlencode(query),""))
    except ValueError:return value


def likely_placeholder(value: str) -> bool:
    low=value.lower()
    return any(x in low for x in ("example","sample","placeholder","your_","your-","changeme","xxxx","dummy","test_key","test-key"))


class ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, domain: str): self.domain=domain
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        host=urllib.parse.urlsplit(newurl).hostname or ""
        if not in_scope_host(host,self.domain): raise urllib.error.HTTPError(newurl,code,"out-of-scope redirect blocked",headers,fp)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


class FormParser(HTMLParser):
    """Small, dependency-free form inventory parser."""
    def __init__(self) -> None:
        super().__init__(); self.forms: list[dict[str, Any]]=[]; self.current: dict[str, Any] | None=None
    def handle_starttag(self, tag: str, attrs: list[tuple[str,str | None]]) -> None:
        values={k.lower():(v or "") for k,v in attrs}
        if tag.lower()=="form":
            self.current={"action":values.get("action",""),"method":values.get("method","get").lower(),"inputs":[]};self.forms.append(self.current)
        elif tag.lower() in {"input","textarea","select"} and self.current is not None:
            name=values.get("name","").strip();kind=values.get("type","text" if tag.lower()!="select" else "select").lower()
            if name:self.current["inputs"].append({"name":name,"type":kind,"value":values.get("value","")})
    def handle_endtag(self, tag: str) -> None:
        if tag.lower()=="form":self.current=None


class Pipeline:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.root = cfg.output / f"{cfg.domain}-{stamp}"
        self.raw = self.root / "raw"; self.inputs = self.root / "inputs"
        self.raw.mkdir(parents=True); self.inputs.mkdir()
        self.db = Database(self.root / "recon.sqlite3")
        self.user_agents = UserAgentPool(cfg.user_agent_file)
        self.run_id = self.db.start(cfg.domain, cfg.profile, dataclasses.asdict(cfg) | {"output": str(cfg.output), "wordlist": str(cfg.wordlist) if cfg.wordlist else None, "skip": sorted(cfg.skip), "skip_stages": sorted(cfg.skip_stages), "scope_subdomains": list(cfg.scope_subdomains), "user_agent_file": str(cfg.user_agent_file) if cfg.user_agent_file else None})
        self.done = 0; self.total = 25 if cfg.profile == "deep" else (6 if cfg.profile == "passive" else 16)
        self.encoded_analyzed=0
        self.pipeline_started=time.monotonic()

    def headers(self, purpose: str = "authorized-security-review", extra: dict[str,str] | None = None) -> dict[str,str]:
        headers={"User-Agent":self.user_agents.choose(purpose),"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,text/plain;q=0.7,*/*;q=0.1","Accept-Encoding":"identity","Connection":"close"}
        if extra:headers.update(extra)
        return headers

    def user_agent(self, purpose: str = "authorized-security-review") -> str:
        return self.user_agents.choose(purpose)

    def host_allowed(self, host: str) -> bool:
        return host_in_scope_entries(host, self.cfg.domain, self.cfg.scope_subdomains)

    def scope_search_domains(self) -> list[str]:
        if not self.cfg.scope_subdomains:
            return [self.cfg.domain]
        domains: set[str] = set()
        for entry in self.cfg.scope_subdomains:
            if entry.startswith("*."):
                domains.add(entry[2:])
            elif "*" in entry:
                parts = entry.split(".")
                star_index = next((idx for idx, part in enumerate(parts) if "*" in part), 0)
                suffix = ".".join(parts[star_index + 1:])
                if suffix and in_scope_host(suffix, self.cfg.domain):
                    domains.add(suffix)
        return sorted(domains or {self.cfg.domain})

    def scope_has_discovery_patterns(self) -> bool:
        return any("*" in entry for entry in self.cfg.scope_subdomains)

    def exact_scope_hosts(self) -> set[str]:
        return {entry for entry in self.cfg.scope_subdomains if "*" not in entry and DOMAIN_RE.fullmatch(entry)}

    def should_preflight_active_scope(self) -> bool:
        return bool(self.cfg.profile != "passive" and self.exact_scope_hosts() and not self.scope_has_discovery_patterns() and "http" not in self.cfg.skip_stages)

    def log(self, message: str, color: str = "cyan") -> None:
        use = sys.stderr.isatty() and not os.getenv("NO_COLOR")
        eta=""
        if self.done:
            remaining=max(0,self.total-self.done);seconds=int((time.monotonic()-self.pipeline_started)/self.done*remaining)
            eta=f" ETA {seconds//60:02d}:{seconds%60:02d}"
        prefix = f"[{self.done}/{self.total}{eta}]"
        print(f"{ANSI[color] if use else ''}{prefix} {message}{ANSI['reset'] if use else ''}", file=sys.stderr, flush=True)

    def tool(self, *names: str) -> str | None:
        for name in names:
            base=Path(__file__).resolve().parent
            for local in (base/"bin"/name,base/"tools"/"bin"/name):
                if local.is_file() and os.access(local, os.X_OK):return str(local)
            found = shutil.which(name)
            if found:
                return found
        return None

    async def run_tool(self, stage: str, name: str, args: list[str], timeout: int | None = None, stdin: Path | None = None, executable: str | None = None, env: dict[str,str] | None = None, cwd: Path | None = None, artifact_name: str | None = None, success_codes: set[int] | None = None) -> tuple[int, Path]:
        exe = executable or self.tool(name)
        artifact = re.sub(r"[^A-Za-z0-9_.-]+", "-", artifact_name or name).strip("-") or name
        out = self.raw / f"{stage}-{artifact}.stdout"; err = self.raw / f"{stage}-{artifact}.stderr"
        if not exe or name in self.cfg.skip:
            self.log(f"{stage}: {name} unavailable/skipped", "yellow")
            self.db.execute("INSERT INTO tool_runs(run_id,stage,tool,command_json,started_at,duration,exit_code,status,stdout_path,stderr_path) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.run_id,stage,name,json.dumps(args),utcnow(),0,None,"skipped",str(out),str(err))); self.db.conn.commit()
            return 127, out
        command = [exe, *args]; started = utcnow(); before = time.monotonic()
        self.log(f"{stage}: running {name}")
        with out.open("wb") as stdout, err.open("wb") as stderr, (stdin.open("rb") if stdin else open(os.devnull, "rb")) as input_fh:
            proc = await asyncio.create_subprocess_exec(*command, stdin=input_fh, stdout=stdout, stderr=stderr, start_new_session=True,env=env,cwd=cwd)
            try:
                code = await asyncio.wait_for(proc.wait(), timeout=timeout or self.cfg.timeout * 20)
                status = "ok" if code in (success_codes or {0}) else "failed"
            except asyncio.TimeoutError:
                os.killpg(proc.pid, signal.SIGTERM)
                try: await asyncio.wait_for(proc.wait(), 3)
                except asyncio.TimeoutError: os.killpg(proc.pid, signal.SIGKILL); await proc.wait()
                code, status = 124, "timeout"
        self.db.execute("INSERT INTO tool_runs(run_id,stage,tool,command_json,started_at,duration,exit_code,status,stdout_path,stderr_path) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.run_id,stage,name,json.dumps(command),started,time.monotonic()-before,code,status,str(out),str(err))); self.db.conn.commit()
        return code, out

    def write_input(self, name: str, values: Iterable[str]) -> Path:
        path = self.inputs / name
        path.write_text("".join(f"{v}\n" for v in sorted(set(values))))
        return path

    def seed_scope_assets(self) -> None:
        seeds={self.cfg.domain,*[entry for entry in self.cfg.scope_subdomains if "*" not in entry]}
        for host in sorted(seeds):
            if self.host_allowed(host) and DOMAIN_RE.fullmatch(host):
                self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"scope-input" if host!=self.cfg.domain else "apex",utcnow()))
        self.db.conn.commit()

    async def preflight_active_scope(self) -> bool:
        hosts=sorted(self.exact_scope_hosts())
        if not hosts:
            return True
        before=time.monotonic()
        self.log(f"00-scope-preflight: checking {len(hosts)} scoped host(s) for active HTTP service")
        for host in hosts:
            if self.host_allowed(host):
                self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"scope-input",utcnow()))
        resolved=await self.resolve_host_batch(hosts,"scope-preflight-dnsx")
        await self.probe_http_batch(resolved,"scope-preflight-httpx")
        active=set(self.db.values("SELECT hostname FROM assets WHERE run_id=? AND http_active=1",(self.run_id,))) & set(hosts)
        inactive=sorted(set(hosts)-active)
        for host in inactive:
            self.db.execute("DELETE FROM dns_records WHERE run_id=? AND hostname=?",(self.run_id,host))
            self.db.execute("DELETE FROM assets WHERE run_id=? AND hostname=? AND source='scope-input'",(self.run_id,host))
        self.db.conn.commit()
        message=f"{len(active)} active scoped host(s), {len(inactive)} inactive skipped"
        self.log(f"00-scope-preflight: {message}","green" if active else "yellow")
        self.record_stage("00-scope-preflight","ok" if active else "skipped",message,time.monotonic()-before)
        return bool(active)

    def record_stage(self, stage: str, status: str, message: str, duration: float = 0.0) -> None:
        self.db.execute("INSERT INTO tool_runs(run_id,stage,tool,command_json,started_at,duration,exit_code,status,stdout_path,stderr_path) VALUES(?,?,?,?,?,?,?,?,?,?)",(self.run_id,stage,"pipeline-stage",json.dumps({"message":message}),utcnow(),duration,None,status,"",""))
        self.db.conn.commit()

    async def run_step(self, stage_key: str, label: str, action: Any) -> None:
        if stage_key in self.cfg.skip_stages:
            self.log(f"{label}: stage skipped by scan policy","yellow")
            self.record_stage(label,"skipped","stage skipped by scan policy")
            self.done+=1
            return
        before=time.monotonic()
        before_done=self.done
        try:
            await action()
            if self.done==before_done:self.done+=1
        except Exception as exc:
            self.log(f"{label}: failed ({type(exc).__name__}: {exc}); continuing","red")
            self.record_stage(label,"failed",f"{type(exc).__name__}: {exc}",time.monotonic()-before)
            self.done+=1

    async def domain_intelligence(self) -> None:
        code,out=await self.run_tool("00-domain","whois",[self.cfg.domain],timeout=120)
        if code==0:
            wanted={"registrar","registrar name","creation date","created","created date","registry expiry date","expiration date","expiry date","updated date","last updated","name server","nserver","dnssec","domain status","status","registrant organization","registrant country"}
            for line in out.read_text(errors="replace").splitlines():
                match=re.match(r"^\s*([^:%]{2,60}):\s*(.*?)\s*$",line)
                if not match:continue
                key,value=match.group(1).strip(),match.group(2).strip()
                if key.lower() in wanted and value:
                    self.db.execute("INSERT OR IGNORE INTO domain_info(run_id,key,value,source) VALUES(?,?,?,?)",(self.run_id,key,value,"whois"))
        def rdap_lookup() -> dict[str,Any] | None:
            request=urllib.request.Request("https://rdap.org/domain/"+urllib.parse.quote(self.cfg.domain),headers=self.headers("authorized-rdap",{"Accept":"application/rdap+json, application/json"}))
            try:
                with urllib.request.urlopen(request,timeout=self.cfg.timeout) as response:
                    return json.loads(response.read(5_000_000))
            except (urllib.error.URLError,TimeoutError,ValueError,json.JSONDecodeError):return None
        rdap=None if "rdap" in self.cfg.skip else await asyncio.to_thread(rdap_lookup)
        if isinstance(rdap,dict):
            (self.raw/"00-domain-rdap.json").write_text(json.dumps(rdap,indent=2,sort_keys=True))
            facts:list[tuple[str,str]]=[]
            for key,label in (("handle","Registry handle"),("ldhName","Domain")):
                if rdap.get(key):facts.append((label,str(rdap[key])))
            facts.extend(("Status",str(x)) for x in rdap.get("status",[]) if x)
            facts.extend((str(x.get("eventAction","Event")).replace("_"," ").title(),str(x.get("eventDate"))) for x in rdap.get("events",[]) if isinstance(x,dict) and x.get("eventDate"))
            facts.extend(("Name server",str(x.get("ldhName"))) for x in rdap.get("nameservers",[]) if isinstance(x,dict) and x.get("ldhName"))
            secure=rdap.get("secureDNS") or {}
            if isinstance(secure,dict) and "delegationSigned" in secure:facts.append(("DNSSEC signed",str(bool(secure["delegationSigned"]))))
            for entity in rdap.get("entities",[]):
                if not isinstance(entity,dict) or "registrar" not in (entity.get("roles") or []):continue
                vcard=entity.get("vcardArray") or [None,[]]
                properties=vcard[1] if isinstance(vcard,list) and len(vcard)>1 and isinstance(vcard[1],list) else []
                for item in properties:
                    if isinstance(item,list) and len(item)>3 and item[0]=="fn":facts.append(("Registrar",str(item[3])))
            for key,value in facts:self.db.execute("INSERT OR IGNORE INTO domain_info(run_id,key,value,source) VALUES(?,?,?,?)",(self.run_id,key,value,"rdap"))
        self.db.conn.commit();self.done+=1

    async def recon_ng(self) -> None:
        exe=self.tool("recon-ng")
        prefix:list[str]=[]
        local_framework=Path(__file__).resolve().parent/"tools/recon-ng/recon-ng"
        if not exe and local_framework.exists():
            isolated=Path(__file__).resolve().parent/"tools/recon-ng/.venv/bin/python"
            fallback=Path(__file__).resolve().parent/"venv/bin/python"
            exe=str(isolated if isolated.exists() else (fallback if fallback.exists() else Path(sys.executable)));prefix=[str(local_framework)]
        marketplace=Path(__file__).resolve().parent/"tools/recon-ng-marketplace/modules/recon/domains-hosts"
        if not exe or not marketplace.exists() or "recon-ng" in self.cfg.skip:
            self.log("00-osint: recon-ng or local marketplace unavailable/skipped","yellow");self.done+=1;return
        home=self.root/"recon-home"; modules=home/".recon-ng/modules/recon/domains-hosts";modules.mkdir(parents=True)
        selected=("certificate_transparency.py","hackertarget.py","threatminer.py","mx_spf_ip.py")
        for name in selected:
            source=marketplace/name
            if source.exists():shutil.copy2(source,modules/name)
        workspace=f"scan_{self.run_id}"
        resource=self.inputs/"recon-ng.rc"
        commands=[f"db query INSERT INTO domains (domain) VALUES ('{self.cfg.domain}')"]
        for module in ("certificate_transparency","hackertarget","threatminer","mx_spf_ip"):
            commands += [f"modules load recon/domains-hosts/{module}","run","back"]
        commands += ["show hosts","exit"]
        resource.write_text("\n".join(commands)+"\n")
        env=os.environ.copy();env.update({"HOME":str(home),"XDG_CACHE_HOME":str(home/"cache"),"XDG_CONFIG_HOME":str(home/"config")})
        await self.run_tool("00-osint","recon-ng",prefix+["-w",workspace,"-r",str(resource),"--no-version","--no-analytics","--no-marketplace"],timeout=900,executable=exe,env=env)
        database=home/".recon-ng/workspaces"/workspace/"data.db"
        if database.exists():
            recon=sqlite3.connect(database);recon.row_factory=sqlite3.Row
            try:
                for row in recon.execute("SELECT host,ip_address,module FROM hosts"):
                    host=str(row["host"] or "").lower().lstrip("*.").rstrip(".")
                    if self.host_allowed(host) and DOMAIN_RE.fullmatch(host):
                        self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"recon-ng:"+str(row["module"] or "unknown"),utcnow()))
                        if row["ip_address"]:self.db.execute("INSERT OR IGNORE INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(self.run_id,host,"A",str(row["ip_address"]),"recon-ng"))
            finally:recon.close()
        self.db.conn.commit();self.done+=1

    async def additional_osint(self) -> None:
        base=Path(__file__).resolve().parent
        harvester=base/"tools/theHarvester/.venv/bin/theHarvester"
        if harvester.exists() and "theharvester" not in self.cfg.skip:
            home=self.root/"harvester-home";home.mkdir();env=os.environ.copy();env["HOME"]=str(home)
            prefix=self.raw/"theharvester"
            await self.run_tool("00-osint","theharvester",["-d",self.cfg.domain,"-b","crtsh,duckduckgo,hackertarget,rapiddns,threatcrowd,urlscan,waybackarchive,otx","-l","200","-q","-f",str(prefix)],timeout=900,executable=str(harvester),env=env)
            candidates=[prefix.with_suffix(".json"),Path(str(prefix)+".json")]
            for path in candidates:
                if not path.exists():continue
                text=path.read_text(errors="replace")
                for host in set(re.findall(rf"(?i)\b(?:[a-z0-9-]+\.)+{re.escape(self.cfg.domain)}\b",text)):
                    host=host.lower()
                    if self.host_allowed(host):
                        self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"theHarvester",utcnow()))
                for email in set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",text)):
                    self.db.execute("INSERT OR IGNORE INTO domain_info(run_id,key,value,source) VALUES(?,?,?,?)",(self.run_id,"Public email",email,"theHarvester"))
        spider=base/"tools/spiderfoot/sf.py";spython=base/"tools/spiderfoot/.venv/bin/python"
        if spider.exists() and spython.exists() and "spiderfoot" not in self.cfg.skip:
            shome=self.root/"spiderfoot-home";shome.mkdir();senv=os.environ.copy();senv["HOME"]=str(shome)
            code,out=await self.run_tool("00-osint","spiderfoot",[str(spider),"-s",self.cfg.domain,"-u","passive","-o","json","-q","-max-threads","3"],timeout=900,executable=str(spython),cwd=spider.parent,env=senv)
            if code==0:
                text=out.read_text(errors="replace")
                for host in set(re.findall(rf"(?i)\b(?:[a-z0-9-]+\.)+{re.escape(self.cfg.domain)}\b",text)):
                    host=host.lower()
                    if self.host_allowed(host):
                        self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"spiderfoot",utcnow()))
        self.db.conn.commit()

    async def dns_intelligence(self) -> None:
        record_types=("A","AAAA","MX","NS","TXT","CAA","SOA")
        dig=self.tool("dig")
        if dig and "dig" not in self.cfg.skip:
            for typ in record_types:
                code,out=await self.run_tool("02-dns",f"dig-{typ.lower()}",["+noall","+answer",self.cfg.domain,typ],timeout=60,executable=dig)
                if code!=0:continue
                for line in out.read_text(errors="replace").splitlines():
                    parts=line.split(None,4)
                    if len(parts)==5 and parts[3].upper()==typ:
                        self.db.execute("INSERT OR IGNORE INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(self.run_id,parts[0].rstrip(".").lower(),typ,parts[4].strip(),"dig"))
        dns_python=Path(__file__).resolve().parent/"venv/bin/python"
        shim="import urllib.request; urllib.request.FancyURLopener=object; from dnsrecon.__main__ import main; main()"
        if dns_python.exists() and "dnsrecon" not in self.cfg.skip:await self.run_tool("02-dns","dnsrecon",["-c",shim,"-d",self.cfg.domain,"-t","std"],timeout=300,executable=str(dns_python))
        else:await self.run_tool("02-dns","dnsrecon",["-d",self.cfg.domain,"-t","std"],timeout=300)
        dnsenum_script=Path(__file__).resolve().parent/"tools/dnsenum/dnsenum.pl"
        if not self.tool("dnsenum") and dnsenum_script.exists() and self.tool("perl"):
            await self.run_tool("02-dns","dnsenum",[str(dnsenum_script),"--noreverse",self.cfg.domain],timeout=300,executable=self.tool("perl"),cwd=dnsenum_script.parent)
        else:await self.run_tool("02-dns","dnsenum",["--noreverse",self.cfg.domain],timeout=300)
        self.db.conn.commit();self.done+=1

    async def enumerate(self) -> None:
        basename = self.raw / "ducky-subs"
        enumerator = self.tool("ducky-subs")
        if enumerator:
            args = ["-d", self.cfg.domain, "-o", str(basename), "-t", str(self.cfg.concurrency), "-depth", str(self.cfg.depth), "-timeout", f"{self.cfg.timeout}s"]
            if self.cfg.profile == "passive": args.append("--passive")
            await self.run_tool("01-enumerate", "ducky-subs", args, timeout=1800, executable=enumerator)
        else:
            # ducky-subs is a local/private binary; subfinder is the portable,
            # maintained fallback installed by setup.py.
            output = basename.with_suffix(".txt")
            args = ["-d", self.cfg.domain, "-o", str(output), "-silent", "-t", str(self.cfg.concurrency), "-timeout", str(self.cfg.timeout)]
            if self.cfg.profile != "passive": args.append("-recursive")
            await self.run_tool("01-enumerate", "subfinder", args, timeout=1800)
        candidates = {self.cfg.domain}
        for path in [basename.with_suffix(".txt"), basename.with_suffix(".live.txt")]:
            if path.exists():
                candidates.update(x.strip().lower() for x in path.read_text(errors="replace").splitlines())
        for host in candidates:
            if self.host_allowed(host) and DOMAIN_RE.fullmatch(host):
                self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)", (self.run_id,host,"ducky-subs",utcnow()))
        self.db.conn.commit(); self.done += 1

    async def resolve(self) -> None:
        hosts = self.db.values("SELECT hostname FROM assets WHERE run_id=?", (self.run_id,))
        await self.resolve_host_batch(hosts,"dnsx-initial")
        self.db.conn.commit(); self.done += 1

    async def resolve_host_batch(self, hosts: Iterable[str], artifact_name: str) -> set[str]:
        values=sorted({host for host in hosts if self.host_allowed(host) and DOMAIN_RE.fullmatch(host)})
        if not values:return set()
        inp=self.write_input(artifact_name+".txt",values)
        code, out = await self.run_tool("02-resolve", "dnsx", ["-l", str(inp), "-a", "-aaaa", "-cname", "-resp", "-json", "-silent", "-rl", str(self.cfg.rate), "-t", str(self.cfg.concurrency)],artifact_name=artifact_name)
        resolved=set()
        if code == 0:
            for row in json_lines(out):
                host = str(row.get("host") or row.get("input") or "").lower()
                if not self.host_allowed(host): continue
                values = row.get("a", []) + row.get("aaaa", []) + row.get("cname", [])
                for value in values:
                    typ = "AAAA" if ":" in str(value) else ("A" if re.fullmatch(r"[\d.]+",str(value)) else "CNAME")
                    self.db.execute("INSERT OR IGNORE INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)", (self.run_id,host,typ,str(value),"dnsx"))
                if values:self.db.execute("UPDATE assets SET resolved=1 WHERE run_id=? AND hostname=?",(self.run_id,host));resolved.add(host)
        self.db.conn.commit();return resolved

    async def active_dns_enumeration(self) -> None:
        """Resolve common subdomain labels with bundled Gobuster before dnsx."""
        base=Path(__file__).resolve().parent
        wordlist=base/"wordlists/subdomains-top1million-5000.txt"
        if not wordlist.is_file():
            self.log("01-active-dns: bundled subdomain wordlist unavailable","yellow");self.done+=1;return
        workers=min(self.cfg.concurrency,max(1,self.cfg.rate),50)
        delay_ms=max(1,math.ceil(1000*workers/self.cfg.rate))
        with wordlist.open(errors="replace") as handle:
            word_count=sum(1 for line in handle if line.strip() and not line.lstrip().startswith("#"))
        stage_timeout=max(1800,math.ceil(word_count/max(1,self.cfg.rate))*2+self.cfg.timeout*2)
        search_domains=self.scope_search_domains()
        if self.cfg.scope_subdomains and not self.scope_has_discovery_patterns():
            self.log("01-active-dns: exact scoped hosts supplied; wildcard DNS enumeration skipped","yellow");self.done+=1;return
        for search_domain in search_domains:
            args=["dns","--domain",search_domain,"--wordlist",str(wordlist),"--check-cname","--threads",str(workers),"--delay",f"{delay_ms}ms","--timeout",f"{self.cfg.timeout}s","--quiet","--no-progress","--no-color"]
            _,out=await self.run_tool("01-active-dns","gobuster",args,timeout=stage_timeout,artifact_name=f"gobuster-dns-{search_domain}")
            for raw in out.read_text(errors="replace").splitlines() if out.exists() else []:
                line=re.sub(r"\x1b\[[0-9;]*m","",raw).strip()
                if not line:continue
                host=line.split(None,1)[0].lower().rstrip(".")
                if not self.host_allowed(host) or not DOMAIN_RE.fullmatch(host):continue
                self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,resolved,first_seen) VALUES(?,?,?,?,?)",(self.run_id,host,"gobuster-dns",1,utcnow()))
                remainder=line[len(line.split(None,1)[0]):].strip();cname=""
                if " CNAME: " in " "+remainder:
                    remainder,cname=(" "+remainder).split(" CNAME: ",1);remainder=remainder.strip()
                for candidate in remainder.replace(","," ").split():
                    try:ipaddress.ip_address(candidate)
                    except ValueError:continue
                    typ="AAAA" if ":" in candidate else "A"
                    self.db.execute("INSERT OR IGNORE INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(self.run_id,host,typ,candidate,"gobuster-dns"))
                if cname:
                    self.db.execute("INSERT OR IGNORE INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(self.run_id,host,"CNAME",cname.rstrip("."),"gobuster-dns"))
        self.db.conn.commit();self.done+=1

    async def archive_discovery(self) -> None:
        """Feed historical URLs and hosts into deep DNS/HTTP discovery."""
        inp=self.write_input("archive-domains.txt",[self.cfg.domain])
        code,out=await self.run_tool("01-archive","waybackurls",[],timeout=1800,stdin=inp)
        discovered=[];hosts=set()
        if out.exists():
            for line in out.read_text(errors="replace").splitlines():
                url=canonical_url(line.strip(),self.cfg.domain)
                if not url:continue
                parsed=urllib.parse.urlsplit(url)
                if not parsed.hostname or not self.host_allowed(parsed.hostname):continue
                discovered.append(url)
                host=parsed.hostname
                if host:hosts.add(host)
        for host in sorted(hosts):
            if self.host_allowed(host):
                self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"waybackurls",utcnow()))
        def priority(url: str) -> tuple[int,str]:
            parsed=urllib.parse.urlsplit(url);ext=Path(parsed.path).suffix.lower()
            return (0 if ext in {".js",".mjs",".map",".json"} else (1 if parsed.query else 2),url)
        archive_budget=max(1,self.cfg.max_urls//2)
        for url in sorted(set(discovered),key=priority)[:archive_budget]:self.add_endpoint(url,"waybackurls")
        self.db.conn.commit();self.done+=1

    def ingest_subjack(self, path: Path, hosts: set[str]) -> None:
        try:data=json.loads(path.read_text(errors="replace"))
        except (OSError,json.JSONDecodeError):return
        if isinstance(data,dict):
            records=data.get("results",data.get("findings",[data]))
        else:records=data
        if not isinstance(records,list):return
        signals=("vulnerable","takeover","claimable","dangling","stale a record","zone transfer","expired")
        for item in records:
            if not isinstance(item,dict):continue
            host=str(item.get("subdomain") or item.get("domain") or item.get("host") or "").lower().rstrip(".")
            text=json.dumps(item,sort_keys=True);low=text.lower()
            positive=item.get("vulnerable") is True or (item.get("vulnerable") is not False and "not vulnerable" not in low and any(x in low for x in signals))
            if host in hosts and self.host_allowed(host) and positive:
                service=str(item.get("service") or item.get("type") or "unknown service")
                self.add_tool_finding("subjack","high",f"Potential subdomain takeover: {service}",f"https://{host}/",text)

    async def takeover_checks(self) -> None:
        hosts=self.db.values("SELECT hostname FROM assets WHERE run_id=?",(self.run_id,));host_set=set(hosts);inp=self.write_input("all-subdomains.txt",hosts)
        self.log(f"03-takeover: checking {len(hosts)} discovered hosts")
        base=Path(__file__).resolve().parent;subover=self.tool("subover");subout=self.raw/"takeover-subover.txt"
        if subover and "subover" not in self.cfg.skip:
            source=base/"tools/SubOver"
            code,out=await self.run_tool("03-takeover","subover",["-l",str(inp),"-o",str(subout),"-t",str(min(10,self.cfg.concurrency)),"-timeout",str(self.cfg.timeout)],timeout=1800,executable=subover,cwd=source if source.exists() else base)
            evidence=(subout.read_text(errors="replace") if subout.exists() else out.read_text(errors="replace"))
            for line in evidence.splitlines():
                if any(word in line.lower() for word in ("vulnerable","takeover","can be claimed")):
                    host=next((h for h in hosts if h in line),self.cfg.domain);self.add_tool_finding("subover","high","Potential subdomain takeover",f"https://{host}/",line)
        subjack=self.tool("subjack");subjack_out=self.raw/"takeover-subjack.json"
        if self.cfg.profile=="deep" and subjack and "subjack" not in self.cfg.skip:
            workers=min(25,self.cfg.concurrency,max(1,self.cfg.rate))
            await self.run_tool("03-takeover","subjack",["-w",str(inp),"-a","-ssl","-ns","-mail","-t",str(workers),"-timeout",str(self.cfg.timeout),"-o",str(subjack_out)],timeout=3600,executable=subjack)
            if subjack_out.exists():self.ingest_subjack(subjack_out,host_set)
        if self.tool("nuclei") and "nuclei" not in self.cfg.skip:
            code,out=await self.run_tool("03-takeover","nuclei-takeover",["-l",str(inp),"-tags","takeover","-jsonl","-silent","-rl",str(min(self.cfg.rate,25)),"-c",str(min(self.cfg.concurrency,10)),"-timeout",str(self.cfg.timeout),"-retries","1","-or"],timeout=1800,executable=self.tool("nuclei"))
            for row in json_lines(out):
                info=row.get("info",{}) or {};matched=str(row.get("matched-at") or row.get("host") or "")
                host=urllib.parse.urlsplit(matched).hostname or matched.split(":")[0]
                if self.host_allowed(host):self.add_tool_finding("nuclei-takeover",str(info.get("severity") or "high"),str(info.get("name") or "Potential subdomain takeover"),matched,json.dumps(row))
        self.db.conn.commit();self.done+=1

    async def ports(self) -> None:
        hosts = self.db.values("SELECT hostname FROM assets WHERE run_id=? AND resolved=1",(self.run_id,)); inp=self.write_input("resolved.txt",hosts)
        args=["-list",str(inp),"-json","-silent","-rate",str(self.cfg.rate),"-c",str(self.cfg.concurrency),"-exclude-cdn"]
        args += ["-top-ports", "1000" if self.cfg.profile == "deep" else "100"]
        code,out=await self.run_tool("03-ports","naabu",args,timeout=3600)
        if code==0:
            for row in json_lines(out):
                host=str(row.get("host") or ""); ip=str(row.get("ip") or "")
                self.db.execute("INSERT OR IGNORE INTO ports(run_id,hostname,ip,port,protocol,service,source) VALUES(?,?,?,?,?,?,?)",(self.run_id,host,ip,int(row.get("port",0)),str(row.get("protocol","tcp")),"","naabu"))
        self.db.conn.commit()
        open_ports=sorted({int(x) for x in self.db.values("SELECT port FROM ports WHERE run_id=?",(self.run_id,))})
        ips=self.db.values("SELECT value FROM dns_records WHERE run_id=? AND type IN ('A','AAAA') UNION SELECT ip FROM ports WHERE run_id=? AND ip!='' ORDER BY 1",(self.run_id,self.run_id))
        if ips and self.tool("nmap") and "nmap" not in self.cfg.skip:
            families=(("ipv4",[ip for ip in ips if ":" not in ip]),("ipv6",[ip for ip in ips if ":" in ip]))
            for family,family_ips in families:
                if not family_ips:continue
                ip_input=self.write_input(f"resolved-{family}.txt",family_ips);family_args=["-6"] if family=="ipv6" else []
                if self.cfg.profile=="deep":
                    nmap_args=family_args+["-Pn","-n","-sT","-sV","--version-intensity","7","-sC","--script-timeout","2m","-T3","--max-rate",str(self.cfg.rate),"--max-retries","2","--host-timeout","45m","--open","-p-","-iL",str(ip_input),"-oX","-"]
                    nmap_timeout=max(7200,math.ceil(65535*len(family_ips)/max(1,self.cfg.rate))*2+self.cfg.timeout)
                elif open_ports:
                    nmap_args=family_args+["-Pn","-n","-sT","-sV","--version-intensity","7","-sC","--script-timeout","90s","-T3","--max-rate",str(self.cfg.rate),"--max-retries","2","--host-timeout","15m","--open","-p",",".join(map(str,open_ports)),"-iL",str(ip_input),"-oX","-"]
                    nmap_timeout=3600
                else:continue
                ncode,nstdout=await self.run_tool("03-services","nmap",nmap_args,timeout=nmap_timeout,artifact_name=f"nmap-{family}-detailed")
                if ncode==0:self.ingest_nmap_xml(nstdout)
        self.db.conn.commit(); self.done+=1

    def ingest_nmap_xml(self, path: Path) -> None:
        try:root=ET.parse(path).getroot()
        except (OSError,ET.ParseError):self.log("03-services: could not parse nmap XML; raw output preserved","yellow");return
        for host_node in root.findall("host"):
            status_node=host_node.find("status")
            if status_node is not None and str(status_node.get("state") or "up")=="down":continue
            addresses=[node.get("addr","") for node in host_node.findall("address") if node.get("addrtype") in {"ipv4","ipv6"} and node.get("addr")]
            xml_names={str(node.get("name") or "").lower().rstrip(".") for node in host_node.findall("./hostnames/hostname")}
            host_scripts={str(node.get("id") or ""):str(node.get("output") or "")[:4000] for node in host_node.findall("./hostscript/script") if node.get("id")}
            for ip in addresses:
                mapped=set(self.db.values("SELECT hostname FROM dns_records WHERE run_id=? AND type IN ('A','AAAA') AND value=?",(self.run_id,ip)))
                mapped.update(name for name in xml_names if self.host_allowed(name) and DOMAIN_RE.fullmatch(name))
                for port_node in host_node.findall("./ports/port"):
                    state_node=port_node.find("state");state=str(state_node.get("state") or "") if state_node is not None else ""
                    if state!="open":continue
                    port=int(port_node.get("portid","0"));protocol=str(port_node.get("protocol") or "tcp")
                    service_node=port_node.find("service");attrs=service_node.attrib if service_node is not None else {}
                    service=str(attrs.get("name") or "");tunnel=str(attrs.get("tunnel") or "")
                    if tunnel and tunnel not in service:service=f"{tunnel}/{service}" if service else tunnel
                    product=str(attrs.get("product") or "");version=str(attrs.get("version") or "");extra=str(attrs.get("extrainfo") or "")
                    cpes=sorted({str(node.text or "") for node in port_node.findall("./service/cpe") if node.text})
                    scripts=dict(host_scripts);scripts.update({str(node.get("id") or ""):str(node.get("output") or "")[:4000] for node in port_node.findall("script") if node.get("id")})
                    reason=str(state_node.get("reason") or "") if state_node is not None else ""
                    label=" ".join(x for x in (service,product,version,extra) if x)
                    for hostname in sorted(mapped):
                        self.db.execute("""INSERT INTO ports(run_id,hostname,ip,port,protocol,service,state,reason,product,version,extra_info,cpe,scripts,source)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,hostname,ip,port,protocol) DO UPDATE SET
                          service=excluded.service,state=excluded.state,reason=excluded.reason,product=excluded.product,version=excluded.version,
                          extra_info=excluded.extra_info,cpe=excluded.cpe,scripts=excluded.scripts,source='naabu+nmap'""",
                          (self.run_id,hostname,ip,port,protocol,label,state,reason,product,version,extra,json.dumps(cpes),json.dumps(scripts,sort_keys=True),"nmap"))
                        if product:self.add_technology(hostname,"",product,version,"nmap-service","high",label)
                        for cpe in cpes:
                            parsed_cpe=parse_cpe_technology(cpe)
                            if parsed_cpe:self.add_technology(hostname,"",parsed_cpe[0],parsed_cpe[1],"nmap-cpe","high",cpe)
                        for os_name in ("Ubuntu","Debian","CentOS","Red Hat","Windows Server","AlmaLinux","Rocky Linux"):
                            match=re.search(rf"\b{re.escape(os_name)}\b(?:\s+([0-9][A-Za-z0-9._+-]*))?",extra,re.I)
                            if match:self.add_technology(hostname,"",os_name,match.group(1) or "","nmap-service","medium",extra)

    async def probe(self) -> None:
        hosts=self.db.values("SELECT hostname FROM assets WHERE run_id=? AND resolved=1",(self.run_id,))
        pending=set(hosts);seen=set()
        for round_number in range(self.cfg.depth+1):
            targets=sorted(pending-seen)
            if not targets:break
            seen.update(targets);discovered=await self.probe_http_batch(targets,f"httpx-round-{round_number+1:02d}",screenshots=self.cfg.screenshots and round_number==0)
            candidates=[]
            for host in sorted(discovered):
                row=self.db.conn.execute("SELECT resolved,http_active FROM assets WHERE run_id=? AND hostname=?",(self.run_id,host)).fetchone()
                if not row:self.db.execute("INSERT INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"httpx-recursive",utcnow()));candidates.append(host)
                elif not row["resolved"]:candidates.append(host)
            resolved=await self.resolve_host_batch(candidates,f"dnsx-httpx-round-{round_number+1:02d}")
            pending={host for host in resolved if host not in seen}
        self.db.conn.commit(); self.done+=1

    async def probe_open_ports(self) -> None:
        targets=[f"{row['hostname']}:{row['port']}" for row in self.db.conn.execute("SELECT DISTINCT hostname,port FROM ports WHERE run_id=? AND state='open' AND port NOT IN (80,443) ORDER BY hostname,port",(self.run_id,))]
        discovered=await self.probe_http_batch(targets,"httpx-open-ports");seen=set()
        for round_number in range(self.cfg.depth):
            candidates=[]
            for host in sorted(discovered-seen):
                seen.add(host);row=self.db.conn.execute("SELECT resolved,http_active FROM assets WHERE run_id=? AND hostname=?",(self.run_id,host)).fetchone()
                if not row:self.db.execute("INSERT INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host,"httpx-port-recursive",utcnow()));candidates.append(host)
                elif not row["resolved"]:candidates.append(host)
                elif not row["http_active"]:candidates.append(host)
            resolved=await self.resolve_host_batch(candidates,f"dnsx-httpx-open-ports-{round_number+1:02d}")
            probe_targets=set(resolved)|{host for host in candidates if self.db.conn.execute("SELECT resolved FROM assets WHERE run_id=? AND hostname=?",(self.run_id,host)).fetchone()[0]}
            if not probe_targets:break
            discovered=await self.probe_http_batch(probe_targets,f"httpx-open-port-discoveries-{round_number+1:02d}")
        self.db.conn.commit();self.done+=1

    async def probe_http_batch(self, targets: Iterable[str], artifact_name: str, screenshots: bool = False) -> set[str]:
        values=sorted(set(targets));discovered=set()
        if not values:return discovered
        inp=self.write_input(artifact_name+".txt",values)
        args=["-l",str(inp),"-json","-silent","-nf","-efqdn","-sc","-title","-server","-td","-cpe","-ct","-cl","-ip","-cname","-cdn","-location","-fhr","-maxr","5","-http2","-pipeline","-H",f"User-Agent: {self.user_agent('authorized-http-probe')}","-rl",str(self.cfg.rate),"-t",str(self.cfg.concurrency),"-timeout",str(self.cfg.timeout),"-retries","1","-rstr",str(min(self.cfg.secret_max_bytes,2_000_000))]
        if screenshots:args += ["-ss","-esb","-ehb","-srd",str(self.raw/"screenshots")]
        code,out=await self.run_tool("04-http","httpx",args,timeout=3600,executable=self.tool("httpx"),artifact_name=artifact_name)
        if code!=0:return discovered
        for row in json_lines(out):
            url=canonical_url(str(row.get("url") or row.get("input") or ""),self.cfg.domain)
            if not url:continue
            p=urllib.parse.urlsplit(url)
            if not p.hostname or not self.host_allowed(p.hostname):continue
            tech=row.get("tech",[]);tech=tech if isinstance(tech,list) else [tech]
            for cpe in row.get("cpe",[]) if isinstance(row.get("cpe"),list) else []:
                if cpe:tech.append(str(cpe))
            cdn_raw=row.get("cdn_name") or row.get("cdn") or "";cdn_name=str(cdn_raw).strip() if isinstance(cdn_raw,str) else "";cdn_type=str(row.get("cdn_type") or "").strip()
            if cdn_name:tech.append((cdn_type.upper()+":" if cdn_type else "CDN:")+cdn_name)
            status=int(row.get("status_code") or 0)
            self.db.execute("INSERT OR REPLACE INTO http_services(run_id,url,host,status,title,server,technologies,content_type,content_length,ip,final_url,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(self.run_id,url,p.hostname,status,str(row.get("title") or ""),str(row.get("webserver") or ""),json.dumps(sorted(set(tech),key=str.lower)),str(row.get("content_type") or ""),int(row.get("content_length") or 0),str(row.get("host_ip") or row.get("ip") or ""),str(row.get("final_url") or row.get("location") or ""),json.dumps(row)))
            self.infer_http_technologies(url,row);self.sync_service_technologies(url)
            current=self.db.conn.execute("SELECT active_url,http_status FROM assets WHERE run_id=? AND hostname=?",(self.run_id,p.hostname)).fetchone();prior=str(current[0] or "") if current else "";prior_status=int(current[1] or 0) if current else 0
            active_url=url if not prior or (url.startswith("https://") and not prior.startswith("https://")) else prior
            active_status=status if active_url==url else prior_status
            self.db.execute("UPDATE assets SET http_active=1,active_url=?,http_status=? WHERE run_id=? AND hostname=?",(active_url,active_status,self.run_id,p.hostname))
            self.add_endpoint(url,"httpx")
            for key in ("body_fqdn","body_domains"):
                items=row.get(key,[]);items=items if isinstance(items,list) else [items]
                for value in items:
                    host=str(value).lower().strip().rstrip(".")
                    if self.host_allowed(host) and DOMAIN_RE.fullmatch(host):discovered.add(host)
        self.db.conn.commit();return discovered

    def add_endpoint(self, url: str, source: str) -> None:
        current=self.db.conn.execute("SELECT COUNT(*) FROM endpoints WHERE run_id=?",(self.run_id,)).fetchone()[0]
        if current >= self.cfg.max_urls:return
        url=canonical_url(url,self.cfg.domain)
        if not url:return
        p=urllib.parse.urlsplit(url)
        if not p.hostname or not self.host_allowed(p.hostname):return
        keys=sorted({k for k,_ in urllib.parse.parse_qsl(p.query,keep_blank_values=True)}); ext=Path(p.path).suffix.lower().lstrip(".")
        self.db.execute("INSERT OR IGNORE INTO endpoints(run_id,url,host,path,query_keys,extension,source,first_seen) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,url,p.hostname,p.path,json.dumps(keys),ext,source,utcnow()))

    def add_technology(self, host: str, url: str | None, name: str, version: str = "", source: str = "detector", confidence: str = "medium", evidence: str = "") -> None:
        host=str(host or "").lower().rstrip(".")
        if not host or not self.host_allowed(host):
            return
        url=canonical_url(url,self.cfg.domain) if url else ""
        name, parsed_version = split_technology_label(name)
        version=clean_version(version) or parsed_version
        name=" ".join(name.strip().split())
        if not name or name.lower() in WHATWEB_METADATA_PLUGINS:
            return
        category=technology_category(name)
        self.db.execute("""INSERT INTO technologies(run_id,host,url,name,version,category,source,confidence,evidence,first_seen)
          VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,host,url,name,version,source) DO UPDATE SET
          confidence=excluded.confidence,evidence=CASE WHEN excluded.evidence!='' THEN excluded.evidence ELSE technologies.evidence END""",
          (self.run_id,host,url,name,version,category,source,confidence,evidence[:1000],utcnow()))

    def prune_scoped_inventory(self) -> None:
        if not self.cfg.scope_subdomains:
            return

        def allowed_from_url(value: str) -> bool:
            try:
                host = urllib.parse.urlsplit(value).hostname or ""
            except ValueError:
                host = ""
            return bool(host and self.host_allowed(host))

        for table, column in (("assets","hostname"),("dns_records","hostname"),("ports","hostname"),("http_services","host"),("technologies","host")):
            for row_id, host in self.db.conn.execute(f"SELECT id,{column} FROM {table} WHERE run_id=?", (self.run_id,)).fetchall():
                if not self.host_allowed(str(host or "")):
                    self.db.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
        for row_id, host in self.db.conn.execute("SELECT id,host FROM endpoints WHERE run_id=?", (self.run_id,)).fetchall():
            if not self.host_allowed(str(host or "")):
                self.db.execute("DELETE FROM endpoints WHERE id=?", (row_id,))
        for table, column in (("input_points","page_url"),("encoded_artifacts","source_url")):
            for row_id, value in self.db.conn.execute(f"SELECT id,{column} FROM {table} WHERE run_id=?", (self.run_id,)).fetchall():
                if not allowed_from_url(str(value or "")):
                    self.db.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
        for row_id, host, matched_at in self.db.conn.execute("SELECT id,host,matched_at FROM findings WHERE run_id=?", (self.run_id,)).fetchall():
            host = str(host or "")
            allowed = self.host_allowed(host) if host else allowed_from_url(str(matched_at or ""))
            if not allowed:
                self.db.execute("DELETE FROM findings WHERE id=?", (row_id,))
        self.db.conn.commit()

    def sync_service_technologies(self, url: str) -> None:
        service=self.db.conn.execute("SELECT host,server,technologies FROM http_services WHERE run_id=? AND url=?",(self.run_id,url)).fetchone()
        if not service:
            return
        labels=[]
        try:labels.extend(json.loads(service["technologies"] or "[]"))
        except json.JSONDecodeError:pass
        for row in self.db.conn.execute("SELECT name,version FROM technologies WHERE run_id=? AND host=? AND (url=? OR url='')",(self.run_id,service["host"],url)):
            labels.append(technology_label(row["name"],row["version"]))
        for name,version in parse_server_technology(str(service["server"] or "")):
            labels.append(technology_label(name,version))
        self.db.execute("UPDATE http_services SET technologies=? WHERE run_id=? AND url=?",(json.dumps(sorted({x for x in labels if x},key=str.lower)),self.run_id,url))

    def infer_http_technologies(self, url: str, row: dict[str, Any]) -> None:
        parsed=urllib.parse.urlsplit(url);host=parsed.hostname or ""
        server=str(row.get("webserver") or row.get("server") or "")
        for name,version in parse_server_technology(server):
            self.add_technology(host,url,name,version,"httpx-header","high",server)
        tech=row.get("tech",[])
        tech=tech if isinstance(tech,list) else [tech]
        for item in tech:
            name,version=split_technology_label(str(item))
            self.add_technology(host,url,name,version,"httpx-wappalyzer","medium",str(item))
        cpes=row.get("cpe",[]) if isinstance(row.get("cpe"),list) else []
        for cpe in cpes:
            parsed_cpe=parse_cpe_technology(str(cpe))
            if parsed_cpe:
                self.add_technology(host,url,parsed_cpe[0],parsed_cpe[1],"httpx-cpe","high",str(cpe))

    async def deep_http_technology_probe(self) -> None:
        rows=self.db.conn.execute("SELECT url,host,server FROM http_services WHERE run_id=? ORDER BY url LIMIT ?",(self.run_id,min(100,self.cfg.secret_max_files))).fetchall()
        if not rows:
            return
        delay=1/max(1,self.cfg.rate)
        for row in rows:
            for name,version in parse_server_technology(str(row["server"] or "")):
                self.add_technology(str(row["host"]),str(row["url"]),name,version,"server-header","high",str(row["server"] or ""))
            result=self.fetch_text(str(row["url"]))
            await asyncio.sleep(delay)
            if not result:
                continue
            final,text=result
            for name,version,evidence in extract_body_technologies(final,text):
                confidence="high" if version or "generator" in evidence.lower() else "medium"
                self.add_technology(str(row["host"]),str(row["url"]),name,version,"page-source",confidence,evidence)
        for row in rows:
            self.sync_service_technologies(str(row["url"]))

    def add_repository(self, value: str, source: str) -> None:
        try:
            p=urllib.parse.urlsplit(value);parts=[x for x in p.path.split("/") if x]
            if p.hostname not in {"github.com","www.github.com"} or len(parts)<2:return
            owner,repo=parts[0],parts[1].removesuffix(".git")
            if owner.lower() in {"features","marketplace","orgs","settings","topics"} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",repo):return
            url=f"https://github.com/{owner}/{repo}.git"
            self.db.execute("INSERT OR IGNORE INTO repositories(run_id,url,host,source) VALUES(?,?,?,?)",(self.run_id,url,"github.com",source))
        except ValueError:return

    async def crawl(self) -> None:
        urls=self.db.values("SELECT url FROM http_services WHERE run_id=?",(self.run_id,)); inp=self.write_input("live-urls.txt",urls)
        jobs=[("katana",self.run_tool("05-crawl","katana",["-list",str(inp),"-jsonl","-silent","-jc","-kf","all","-fx","-d",str(self.cfg.depth),"-rl",str(self.cfg.rate),"-c",str(min(self.cfg.concurrency,20)),"-p","5","-mdp",str(max(10,self.cfg.max_urls//max(1,len(urls)))),"-fs","rdn","-do"],timeout=3600))]
        if self.tool("gau"):jobs.append(("gau",self.run_tool("05-archive","gau",["--subs",self.cfg.domain],timeout=1800)))
        if self.cfg.profile!="deep" and self.tool("waybackurls"):jobs.append(("waybackurls",self.run_tool("05-wayback","waybackurls",[],timeout=1800,stdin=self.write_input("apex.txt",[self.cfg.domain]))))
        results=await asyncio.gather(*(job for _,job in jobs))
        for (source,_),(_,path) in zip(jobs,results):
            for line in path.read_text(errors="replace").splitlines() if path.exists() else []:
                if line.startswith("{"):
                    try:
                        row=json.loads(line); line=str(row.get("request",{}).get("endpoint") or row.get("url") or "")
                    except json.JSONDecodeError: continue
                for found in URL_RE.findall(line):self.add_repository(found,source);self.add_endpoint(found,source)
                if line.startswith("http"): self.add_endpoint(line,source)
        self.db.conn.execute("DELETE FROM endpoints WHERE id NOT IN (SELECT MIN(id) FROM endpoints WHERE run_id=? GROUP BY url) AND run_id=?",(self.run_id,self.run_id)); self.db.conn.commit(); self.done+=1

    async def javascript_analysis(self) -> None:
        rows=self.db.conn.execute("SELECT url FROM endpoints WHERE run_id=? AND extension IN ('js','mjs') ORDER BY url LIMIT ?",(self.run_id,min(1000,self.cfg.secret_max_files))).fetchall()
        targets=[str(row["url"]) for row in rows]
        miner=self.tool("jsminer")
        if not targets or not miner or "jsminer" in self.cfg.skip:
            self.log("07-jsminer: no JavaScript targets or bundled tool unavailable/skipped","yellow");self.done+=1;return
        inp=self.write_input("jsminer-targets.txt",targets)
        _,out=await self.run_tool("07-jsminer","jsminer",["-quiet","-safe","-endpoints","-external=false","-render=false","-insecure=false","-show-source","-timeout",str(self.cfg.timeout),"-targets",str(inp)],timeout=3600,executable=miner,success_codes={0,1})
        try:data=json.loads(out.read_text(errors="replace"))
        except (OSError,json.JSONDecodeError):data=[]
        records=data if isinstance(data,list) else ([data] if isinstance(data,dict) else [])
        for item in records:
            if not isinstance(item,dict):continue
            source=canonical_url(str(item.get("source") or ""),self.cfg.domain)
            value=str(item.get("value") or item.get("endpoint") or item.get("url") or "").strip()
            if not source or not value or any(x in value for x in ("${","{{","<",">","\\","\n","\r"," ")):continue
            self.add_repository(value,"jsminer")
            found=canonical_url(urllib.parse.urljoin(source,value),self.cfg.domain)
            if found:self.add_endpoint(found,"jsminer")
        self.db.conn.commit();self.done+=1

    async def technologies(self) -> None:
        urls=self.db.values("SELECT url FROM http_services WHERE run_id=?",(self.run_id,)); inp=self.write_input("live-urls.txt",urls)
        output=self.raw/"whatweb.json"
        aggression=3 if self.cfg.profile=="deep" else 1
        args=["--log-json="+str(output),"--no-errors",f"--aggression={aggression}","--follow-redirect=same-site",f"--open-timeout={self.cfg.timeout}",f"--read-timeout={self.cfg.timeout}",f"--user-agent={self.user_agent('authorized-technology-inventory')}","--input-file="+str(inp)]
        if self.cfg.profile=="deep":args += ["--max-threads=1",f"--wait={max(0.01,1/self.cfg.rate):.3f}"]
        else:args += [f"--max-threads={min(25,self.cfg.concurrency,self.cfg.rate)}"]
        await self.run_tool("06-tech","whatweb",args,timeout=3600 if self.cfg.profile=="deep" else 1800)
        if output.exists():
            try:data=json.loads(output.read_text(errors="replace"))
            except json.JSONDecodeError:data=[]
            for row in data if isinstance(data,list) else []:
                url=canonical_url(str(row.get("target") or ""),self.cfg.domain);plugins=row.get("plugins",{})
                if not url or not isinstance(plugins,dict):continue
                labels=[]
                for name,details in plugins.items():
                    if str(name).lower() in WHATWEB_METADATA_PLUGINS:continue
                    versions=details.get("version",[]) if isinstance(details,dict) else []
                    versions=versions if isinstance(versions,list) else [versions]
                    label=str(name)+(":"+",".join(str(v) for v in versions if v) if any(versions) else "")
                    labels.append(label)
                    if any(versions):
                        for version in versions:self.add_technology(urllib.parse.urlsplit(url).hostname or "",url,str(name),str(version),"whatweb","high",label)
                    else:self.add_technology(urllib.parse.urlsplit(url).hostname or "",url,str(name),"","whatweb","medium",label)
                existing=self.db.conn.execute("SELECT technologies FROM http_services WHERE run_id=? AND url=?",(self.run_id,url)).fetchone()
                prior=[]
                if existing:
                    try:prior=json.loads(existing[0] or "[]")
                    except json.JSONDecodeError:pass
                self.db.execute("UPDATE http_services SET technologies=? WHERE run_id=? AND url=?",(json.dumps(sorted(set(prior+labels),key=str.lower)),self.run_id,url))
                self.sync_service_technologies(url)
        await self.deep_http_technology_probe()
        self.db.conn.commit()
        self.done+=1

    def encoded_candidates(self, url: str, text: str) -> list[tuple[str,str,str]]:
        """Return bounded likely encodings/hashes; avoid ordinary words and giant blobs."""
        found=[];seen=set()
        try:
            for key,value in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,keep_blank_values=True):
                if 8<=len(value)<=4096:found.append((f"query:{key}",value,"url-value"))
        except ValueError:pass
        patterns=(
            ("jwt",re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?\b")),
            ("hex-or-hash",re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})(?![A-Fa-f0-9])")),
            ("base64",re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{12,2048}={0,2}(?![A-Za-z0-9+/=_-])")),
            ("percent-encoded",re.compile(r"(?:%[0-9A-Fa-f]{2}){4,256}")),
        )
        for kind,pattern in patterns:
            for match in pattern.finditer(text[:self.cfg.secret_max_bytes]):
                value=match.group(0)
                if kind=="base64" and "=" not in value and (value.isalpha() or not (re.search(r"[A-Z]",value) and re.search(r"[a-z]",value) and re.search(r"\d",value))):continue
                found.append((f"body:{match.start()}",value,kind))
        result=[]
        for location,value,kind in found:
            identity=(location,value)
            if identity not in seen:seen.add(identity);result.append((location,value,kind))
        return result[:20]

    async def analyze_encoded(self, source_url: str, text: str) -> None:
        analyzer=self.tool("ducky-ana")
        for idx,(location,value,hint) in enumerate(self.encoded_candidates(source_url,text)):
            if self.encoded_analyzed>=500:return
            if any(location==f"query:{key}" for key in SECRET_QUERY_KEYS):continue
            is_hash=hint=="hex-or-hash" and len(value) in {32,40,64,96,128}
            preview=redact_secret(value) if is_hash or len(value)>80 else value
            decoded="Hash fingerprint only; hashes are classified and not decrypted." if is_hash else ""
            kind=hint
            if analyzer and "ducky-ana" not in self.cfg.skip:
                try:
                    proc=await asyncio.create_subprocess_exec(analyzer,"-no-color","-max","1024",value,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                    stdout,_=await asyncio.wait_for(proc.communicate(),timeout=10)
                    analysis=stdout.decode(errors="replace")[:4000].replace(value,"[INPUT REDACTED]")
                    low=analysis.lower()
                    if re.search(r"\(hash\s*/",low):is_hash=True
                    decoded=analysis
                    first=next((line.split(":",1)[1].strip() for line in analysis.splitlines() if line.lower().startswith(("type:","encoding:")) and ":" in line),"")
                    if not first:
                        match=re.search(r"\[01\]\s+(.+?)\s{2,}\((?:encoding|hash|token)\s*/",analysis,re.I)
                        first=match.group(1).strip() if match else ""
                    if first:kind=first
                except (OSError,asyncio.TimeoutError):pass
            self.db.execute("INSERT OR IGNORE INTO encoded_artifacts(run_id,source_url,location,kind,value_preview,decoded_preview,is_hash,analyzer) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,source_url,location,kind,preview,decoded[:4000],int(is_hash),"ducky-ana" if analyzer else "built-in classifier"))
            self.encoded_analyzed+=1

    def inventory_forms(self, page_url: str, text: str) -> None:
        parser=FormParser()
        try:parser.feed(text)
        except (ValueError,AssertionError):return
        for form in parser.forms:
            action=canonical_url(urllib.parse.urljoin(page_url,str(form["action"] or page_url)),self.cfg.domain)
            if not action:continue
            method=str(form["method"] or "get").upper()
            for field in form["inputs"]:
                self.db.execute("INSERT OR IGNORE INTO input_points(run_id,page_url,action_url,method,name,input_type) VALUES(?,?,?,?,?,?)",(self.run_id,page_url,action,method,str(field["name"])[:200],str(field["type"])[:40]))

    def fetch_probe(self, url: str) -> tuple[int,str] | None:
        request=urllib.request.Request(url,headers=self.headers("authorized-input-analysis",{"Accept":"text/html,text/plain,application/json"}))
        opener=urllib.request.build_opener(ScopedRedirect(self.cfg.domain),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request,timeout=self.cfg.timeout) as response:
                final=canonical_url(response.geturl(),self.cfg.domain)
                if not final:return None
                return int(response.status),response.read(min(self.cfg.secret_max_bytes,1_000_000)).decode(response.headers.get_content_charset() or "utf-8",errors="replace")
        except (urllib.error.URLError,TimeoutError,ValueError,ssl.SSLError,LookupError):return None

    async def input_checks(self) -> None:
        safe_types={"text","search","url","email","tel","number","select","hidden"};blocked_names={"password","passwd","pass","csrf","token","otp","captcha","card","checkout","delete","logout"}
        rows=self.db.conn.execute("SELECT * FROM input_points WHERE run_id=? AND method='GET' ORDER BY id LIMIT ?",(self.run_id,self.cfg.active_max_urls)).fetchall()
        self.log(f"10-inputs: testing {len(rows)} idempotent GET input points with reflection canaries")
        for idx,row in enumerate(rows):
            name=str(row["name"]);kind=str(row["input_type"]).lower()
            if kind not in safe_types or any(word in name.lower() for word in blocked_names):continue
            marker=f"rp{self.run_id}x{idx}canary"
            p=urllib.parse.urlsplit(row["action_url"]);pairs=urllib.parse.parse_qsl(p.query,keep_blank_values=True);pairs=[(k,v) for k,v in pairs if k!=name]+[(name,marker)]
            probe=canonical_url(urllib.parse.urlunsplit((p.scheme,p.netloc,p.path,urllib.parse.urlencode(pairs),"")),self.cfg.domain)
            if not probe:continue
            result=await asyncio.to_thread(self.fetch_probe,probe);await asyncio.sleep(self.cfg.active_delay)
            context="not reflected"
            if result and marker in result[1]:
                body=result[1];pos=body.find(marker);window=body[max(0,pos-120):pos+len(marker)+120]
                if re.search(r"<[a-z][^>]*(?:value|href|src|data-[\w-]+)=[\"'][^\"']*"+re.escape(marker),window,re.I):context="HTML attribute"
                elif re.search(r"<script\b[^>]*>[\s\S]*"+re.escape(marker),window,re.I):context="script block"
                elif re.search(r">[^<]*"+re.escape(marker),window):context="HTML text"
                else:context="response body"
                severity="medium" if context in {"HTML attribute","script block"} else "low"
                self.add_tool_finding("reflection-probe",severity,"Input reflected in "+context,probe,f"GET field {name!r} reflected a unique inert canary. Reflection is not proof of XSS; validate with the deep XSS scanners.")
            self.db.execute("UPDATE input_points SET tested=1,reflection_context=? WHERE id=?",(context,row["id"]));self.db.conn.commit()
        self.done+=1

    def scan_text(self, url: str, text: str) -> list[dict[str, Any]]:
        found=[]; seen=set()
        for rule in SECRET_RULES:
            for match in rule.pattern.finditer(text):
                value=match.group(1) if match.lastindex else match.group(0)
                if likely_placeholder(value) or (rule.entropy and shannon_entropy(value)<rule.entropy):continue
                fingerprint=hashlib.sha256(value.encode(errors="replace")).hexdigest()[:20]
                key=(rule.name,fingerprint)
                if key in seen:continue
                seen.add(key); line=text.count("\n",0,match.start())+1
                found.append({"type":rule.name,"severity":rule.severity,"url":url,"line":line,"fingerprint":fingerprint,"redacted":redact_secret(value)})
        try:
            query=urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,keep_blank_values=True)
            for key,value in query:
                if key.lower() in SECRET_QUERY_KEYS and len(value)>=8 and not likely_placeholder(value):
                    fingerprint=hashlib.sha256(value.encode()).hexdigest()[:20]
                    found.append({"type":"Sensitive value in URL query","severity":"high","url":url,"line":0,"fingerprint":fingerprint,"redacted":redact_secret(value)})
        except ValueError:pass
        return found

    def fetch_text(self, url: str) -> tuple[str,str] | None:
        request=urllib.request.Request(url,headers=self.headers("authorized-security-review",{"Accept":"text/html,application/javascript,application/json,text/plain,application/xml;q=0.9,*/*;q=0.1"}))
        opener=urllib.request.build_opener(ScopedRedirect(self.cfg.domain),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request,timeout=self.cfg.timeout) as response:
                final=canonical_url(response.geturl(),self.cfg.domain)
                if not final:return None
                ctype=response.headers.get_content_type().lower()
                if not (ctype.startswith("text/") or any(x in ctype for x in ("javascript","json","xml","yaml"))):return None
                raw=response.read(self.cfg.secret_max_bytes+1)
                if len(raw)>self.cfg.secret_max_bytes:return None
                charset=response.headers.get_content_charset() or "utf-8"
                return final,raw.decode(charset,errors="replace")
        except (urllib.error.URLError,TimeoutError,ValueError,ssl.SSLError,LookupError):return None

    async def secrets(self) -> None:
        rows=self.db.conn.execute("SELECT url,extension FROM endpoints WHERE run_id=? ORDER BY CASE WHEN extension IN ('js','map','json') THEN 0 ELSE 1 END,url LIMIT ?",(self.run_id,self.cfg.secret_max_files)).fetchall()
        targets=[r["url"] for r in rows if str(r["extension"] or "").lower() not in SKIP_FETCH_EXTENSIONS]
        targets=list(dict.fromkeys(([r["url"]+".map" for r in rows if str(r["extension"] or "").lower()=="js"]+targets)))[:self.cfg.secret_max_files]
        semaphore=asyncio.Semaphore(min(self.cfg.concurrency,20)); delay=1/max(1,self.cfg.rate)
        sanitized=self.raw/"07-secret-findings.jsonl"; all_findings=[]
        self.log(f"07-secrets: scanning {len(targets)} in-scope text resources")
        async def inspect(url: str) -> None:
            async with semaphore:
                result=await asyncio.to_thread(self.fetch_text,url); await asyncio.sleep(delay)
            if not result:return
            final,text=result
            self.add_endpoint(final,"secret-scanner")
            self.inventory_forms(final,text)
            await self.analyze_encoded(final,text)
            for linked in URL_RE.findall(text):self.add_repository(linked,"page-source")
            for item in self.scan_text(final,text):
                identity=f"{item['type']}:{item['fingerprint']}"
                self.db.execute("INSERT OR IGNORE INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,"secret-scanner",item["severity"],identity,item["type"],final,urllib.parse.urlsplit(final).hostname or "",json.dumps(item,sort_keys=True)))
                all_findings.append(item)
        for start in range(0,len(targets),200):
            await asyncio.gather(*(inspect(url) for url in targets[start:start+200])); self.db.conn.commit()
        mantra=self.tool("mantra")
        mantra_targets=[u for u in targets if Path(urllib.parse.urlsplit(u).path).suffix.lower() in {".js",".mjs",".json",".map"}][:500]
        if mantra_targets and mantra and "mantra" not in self.cfg.skip:
            mantra_input=self.write_input("mantra-urls.txt",mantra_targets)
            _,mantra_out=await self.run_tool("07-secrets","mantra",["-s","-t",str(min(5,self.cfg.concurrency)),"-ua",self.user_agent("authorized-secret-analysis")],timeout=1800,stdin=mantra_input,executable=mantra)
            safe_lines=[]
            for raw_line in mantra_out.read_text(errors="replace").splitlines():
                line=re.sub(r"\x1b\[[0-9;]*m","",raw_line);url_match=URL_RE.search(line)
                chunks=re.findall(r"\[([^\[\]]{8,500})\]",line)
                if not url_match or not chunks:continue
                value=chunks[-1].strip()
                if likely_placeholder(value) or len(value)<12 or (shannon_entropy(value)<3.0 and not any(value.startswith(x) for x in ("AKIA","ASIA","AIza","gh","glpat-","sk-","xox"))):continue
                fingerprint=hashlib.sha256(value.encode(errors="replace")).hexdigest()[:20]
                item={"type":"Mantra secret candidate","severity":"medium","url":url_match.group(0),"line":0,"fingerprint":fingerprint,"redacted":redact_secret(value)}
                safe_lines.append(item);self.add_tool_finding("mantra","medium","Mantra secret candidate",url_match.group(0),json.dumps(item))
            mantra_out.write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in safe_lines))
        with sanitized.open("w") as fh:
            for item in all_findings:fh.write(json.dumps(item,sort_keys=True)+"\n")
        self.db.conn.commit();self.done+=1

    async def repository_secrets(self) -> None:
        repos=self.db.conn.execute("SELECT id,url FROM repositories WHERE run_id=? ORDER BY url LIMIT ?",(self.run_id,self.cfg.repo_max)).fetchall()
        self.log(f"08-repos: scanning {len(repos)} linked repositories with redacted output")
        base=Path(__file__).resolve().parent;clone_root=self.root/"repositories";clone_root.mkdir()
        gitleaks=self.tool("gitleaks");trufflehog=self.tool("trufflehog")
        for idx,row in enumerate(repos):
            repo_url=str(row["url"]);dest=clone_root/f"repo-{idx:03d}"
            code,_=await self.run_tool("08-repos",f"git-clone-{idx:03d}",["clone","--depth","500","--filter=blob:limit=5m","--no-tags",repo_url,str(dest)],timeout=900,executable=self.tool("git"))
            if code!=0:continue
            if gitleaks and "gitleaks" not in self.cfg.skip:
                report=self.raw/f"gitleaks-{idx:03d}.json"
                await self.run_tool("08-repos",f"gitleaks-{idx:03d}",["git",str(dest),"--report-format","json","--report-path",str(report),"--redact=100","--no-banner","--no-color","--max-decode-depth","1","--timeout","300"],timeout=600,executable=gitleaks)
                if report.exists():
                    try:data=json.loads(report.read_text(errors="replace"))
                    except json.JSONDecodeError:data=[]
                    clean=[]
                    for item in data if isinstance(data,list) else []:
                        safe={k:item.get(k) for k in ("Description","File","StartLine","Commit","RuleID","Fingerprint")};clean.append(safe)
                        self.add_tool_finding("gitleaks","high",str(item.get("Description") or item.get("RuleID") or "Repository secret"),repo_url,json.dumps(safe))
                    report.write_text(json.dumps(clean,indent=2))
            if trufflehog and "trufflehog" not in self.cfg.skip:
                _,out=await self.run_tool("08-repos",f"trufflehog-{idx:03d}",["git","file://"+str(dest.resolve()),"--json","--no-verification","--no-update"],timeout=900,executable=trufflehog)
                clean=[]
                for item in json_lines(out):
                    meta=item.get("SourceMetadata",{});safe={"detector":item.get("DetectorName"),"verified":False,"source_metadata":meta,"decoder":item.get("DecoderName")};clean.append(safe)
                    self.add_tool_finding("trufflehog","high","Repository secret: "+str(item.get("DetectorName") or "unknown"),repo_url,json.dumps(safe))
                out.write_text("".join(json.dumps(x)+"\n" for x in clean))
            self.db.execute("UPDATE repositories SET scanned=1 WHERE id=?",(row["id"],));self.db.conn.commit()
        self.done+=1

    async def parameter_discovery(self) -> None:
        venv=Path(__file__).resolve().parent/"venv/bin/arjun";urls=self.db.values("SELECT url FROM http_services WHERE run_id=? ORDER BY url LIMIT ?",(self.run_id,min(20,self.cfg.active_max_urls)))
        targets=self.write_input("arjun-targets.txt",urls);result=self.raw/"arjun.json"
        if not urls or not venv.exists() or "arjun" in self.cfg.skip:self.log("09-parameters: Arjun unavailable/no targets/skipped","yellow");self.done+=1;return
        await self.run_tool("09-parameters","arjun",["-i",str(targets),"-oJ",str(result),"-t","1","--rate-limit",str(max(1,min(5,round(1/self.cfg.active_delay)))),"-T",str(self.cfg.timeout),"-q"],timeout=3600,executable=str(venv))
        if result.exists():
            try:data=json.loads(result.read_text(errors="replace"))
            except json.JSONDecodeError:data={}
            if isinstance(data,dict):
                for url,params in data.items():
                    if not isinstance(params,list):continue
                    p=urllib.parse.urlsplit(str(url));pairs=urllib.parse.parse_qsl(p.query,keep_blank_values=True)+[(str(k),"") for k in params]
                    self.add_endpoint(urllib.parse.urlunsplit((p.scheme,p.netloc,p.path,urllib.parse.urlencode(pairs),"")),"arjun")
        self.db.conn.commit();self.done+=1

    async def tls_checks(self) -> None:
        base=Path(__file__).resolve().parent;targets=[]
        for row in self.db.conn.execute("SELECT DISTINCT host,url FROM http_services WHERE run_id=? AND url LIKE 'https://%' ORDER BY url LIMIT 25",(self.run_id,)):
            p=urllib.parse.urlsplit(row["url"]);targets.append(f"{p.hostname}:{p.port or 443}")
        self.log(f"10-tls: checking {len(targets)} TLS services")
        inp=self.write_input("tls-targets.txt",targets);sslyze=base/"venv/bin/sslyze";ssljson=self.raw/"sslyze.json"
        if targets and sslyze.exists() and "sslyze" not in self.cfg.skip:
            await self.run_tool("10-tls","sslyze",["--targets_in",str(inp),"--json_out",str(ssljson),"--quiet","--slow_connection","--certinfo","--http_headers","--heartbleed","--robot","--reneg","--compression"],timeout=3600,executable=str(sslyze))
            if ssljson.exists():
                try:data=json.loads(ssljson.read_text(errors="replace"));blob=json.dumps(data).lower()
                except json.JSONDecodeError:blob=""
                if '"is_compliant": false' in blob:self.add_tool_finding("sslyze","medium","TLS configuration is not Mozilla-compliant",f"https://{self.cfg.domain}/","See sanitized SSLyze JSON artifact")
        sslscan=self.tool("sslscan")
        if sslscan and "sslscan" not in self.cfg.skip:
            for idx,target in enumerate(targets[:10]):await self.run_tool("10-tls",f"sslscan-{idx:03d}",["--no-colour","--show-certificate",target],timeout=300,executable=sslscan)
        testssl=base/"tools/testssl.sh/testssl.sh"
        if testssl.exists() and "testssl" not in self.cfg.skip:
            for idx,target in enumerate(targets[:5]):
                report=self.raw/f"testssl-{idx:03d}.json"
                await self.run_tool("10-tls",f"testssl-{idx:03d}",["--quiet","--warnings","batch","--connect-timeout",str(self.cfg.timeout),"--openssl-timeout",str(self.cfg.timeout),"--ids-friendly","--severity","LOW","--jsonfile-pretty",str(report),"--overwrite",target],timeout=1200,executable=str(testssl),cwd=testssl.parent)
                if report.exists():
                    try:items=json.loads(report.read_text(errors="replace"))
                    except json.JSONDecodeError:items=[]
                    stack=list(items) if isinstance(items,list) else [items]
                    while stack:
                        item=stack.pop()
                        if isinstance(item,list):stack.extend(item);continue
                        if not isinstance(item,dict):continue
                        stack.extend(v for v in item.values() if isinstance(v,(list,dict)))
                        sev=str(item.get("severity") or "").lower()
                        if sev in {"low","medium","high","critical"} and item.get("finding"):
                            self.add_tool_finding("testssl",sev,str(item.get("id") or "TLS weakness"),f"https://{target}/",str(item.get("finding")))
        self.db.conn.commit();self.done+=1

    async def nikto_checks(self) -> None:
        targets=self.nikto_targets();nikto=self.nikto_executable()
        if not targets or not nikto or "nikto" in self.cfg.skip:self.log("18-nikto: unavailable/no targets/skipped","yellow");self.done+=1;return
        self.log(f"18-nikto: scanning {len(targets)} prioritized web service(s)")
        for idx,target in enumerate(targets):
            report=self.raw/f"nikto-{idx:03d}.xml";tuning=self.nikto_tuning(target);maxtime=max(180,min(900,self.cfg.timeout*30))
            args=["-host",target["url"],"-nointeractive","-ask","no","-Pause",f"{max(self.cfg.active_delay,1/max(1,self.cfg.rate)):.2f}","-maxtime",f"{maxtime}s","-timeout",str(self.cfg.timeout),"-Tuning",tuning,"-Display","V","-Format","xml","-output",str(report),"-useragent",self.user_agent("authorized-nikto-scan")]
            await self.run_tool("18-nikto",f"nikto-{idx:03d}",args,timeout=maxtime+120,executable=nikto,cwd=self.nikto_cwd(),env=self.nikto_env())
            if report.exists():self.ingest_nikto_xml(report,target["url"])
        self.db.conn.commit();self.done+=1

    def nikto_executable(self) -> str | None:
        base=Path(__file__).resolve().parent
        local=base/"tools/nikto/program/nikto.pl"
        if local.is_file() and os.access(local,os.X_OK):return str(local)
        if local.is_file():return str(local)
        return self.tool("nikto")

    def nikto_cwd(self) -> Path | None:
        base=Path(__file__).resolve().parent/"tools/nikto/program"
        return base if base.exists() else None

    def nikto_env(self) -> dict[str,str] | None:
        base=Path(__file__).resolve().parent/"tools/nikto/perl5/lib/perl5"
        if not base.exists():return None
        env=os.environ.copy();prior=env.get("PERL5LIB","")
        env["PERL5LIB"]=str(base)+(os.pathsep+prior if prior else "")
        return env

    def nikto_targets(self) -> list[dict[str,Any]]:
        services=[dict(row) for row in self.db.conn.execute("SELECT url,host,status,server,technologies FROM http_services WHERE run_id=? ORDER BY status,url",(self.run_id,))]
        endpoint_counts=collections.Counter()
        parameter_counts=collections.Counter()
        for row in self.db.conn.execute("SELECT url,query_keys FROM endpoints WHERE run_id=?",(self.run_id,)):
            try:p=urllib.parse.urlsplit(str(row["url"]));origin=urllib.parse.urlunsplit((p.scheme,p.netloc,"/","",""))
            except ValueError:continue
            endpoint_counts[origin]+=1
            if str(row["query_keys"] or "[]")!="[]":parameter_counts[origin]+=1
        targets=[]
        for service in services:
            url=str(service.get("url") or "")
            try:
                p=urllib.parse.urlsplit(url);origin=urllib.parse.urlunsplit((p.scheme,p.netloc,"/","",""))
            except ValueError:continue
            tech=str(service.get("technologies") or "").lower();server=str(service.get("server") or "")
            score=endpoint_counts[origin]+parameter_counts[origin]*3+(5 if any(x in tech for x in ("wordpress","joomla","drupal","php","apache","nginx")) else 0)+(2 if server else 0)
            targets.append({**service,"origin":origin,"score":score})
        seen=set();result=[]
        for target in sorted(targets,key=lambda item:(-int(item["score"]),item["url"])):
            origin=target["origin"]
            if origin in seen:continue
            seen.add(origin);result.append(target)
        limit=8 if self.cfg.profile=="deep" else 4
        return result[:limit]

    def nikto_tuning(self, target: dict[str,Any]) -> str:
        tech=str(target.get("technologies") or "").lower()
        tuning=set("1234567890ab")
        if not any(word in tech for word in ("php","wordpress","joomla","drupal","apache","nginx","iis","tomcat")):
            tuning-=set("79")
        return "".join(ch for ch in "1234567890abcx" if ch in tuning)

    def nikto_severity(self, item: ET.Element) -> str:
        text=" ".join(" ".join((item.findtext(name) or "").lower().split()) for name in ("description","osvdbid","id","namelink"))
        if any(word in text for word in ("remote command","sql injection","xss","shell","rce","authentication bypass","upload")):return "high"
        if any(word in text for word in ("default file","admin","password","disclosure","directory indexing","backup","config","outdated","allowed methods")):return "medium"
        if any(word in text for word in ("header","cookie","httponly","samesite","x-frame-options","csp")):return "low"
        return "info"

    def ingest_nikto_xml(self, report: Path, base_url: str) -> None:
        try:root=ET.parse(report).getroot()
        except (OSError,ET.ParseError):self.log("18-nikto: could not parse XML report; raw output preserved","yellow");return
        for item in root.findall(".//item"):
            desc=" ".join((item.findtext("description") or "").split())
            uri=item.findtext("uri") or item.findtext("iplink") or base_url
            if not desc:continue
            matched=canonical_url(urllib.parse.urljoin(base_url,uri),self.cfg.domain) or base_url
            item_id=item.get("id") or item.findtext("id") or item.get("osvdbid") or item.findtext("osvdbid") or hashlib.sha256((desc+matched).encode()).hexdigest()[:12]
            evidence={child.tag:" ".join((child.text or "").split()) for child in list(item) if child.text}
            self.db.execute("INSERT OR IGNORE INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,"nikto",self.nikto_severity(item),f"nikto:{item_id}",desc[:500],matched,urllib.parse.urlsplit(matched).hostname or "",json.dumps(evidence,sort_keys=True)[:8000]))

    def active_candidates(self) -> list[str]:
        dynamic={"callback","cat","category","dir","file","id","item","keyword","lang","page","path","q","query","redirect","ref","return","s","search","sort","url","view"}
        rows=self.db.values("SELECT url FROM endpoints WHERE run_id=? AND query_keys!='[]'",(self.run_id,)); ranked=[];seen=set()
        for url in rows:
            try:
                p=urllib.parse.urlsplit(url); pairs=urllib.parse.parse_qsl(p.query,keep_blank_values=True);keys={k.lower() for k,_ in pairs}
            except ValueError:continue
            if not pairs or keys & SECRET_QUERY_KEYS:continue
            signature=(p.scheme,p.netloc,p.path,tuple(sorted(keys)))
            if signature in seen:continue
            seen.add(signature);score=10*len(keys&dynamic)+len(keys)
            ranked.append((score,url))
        return [url for _,url in sorted(ranked,key=lambda x:(-x[0],x[1]))[:self.cfg.active_max_urls]]

    def wapiti_executable(self) -> str | None:
        base=Path(__file__).resolve().parent
        candidates=[base/"tools/wapiti/.venv/bin/wapiti",base/"venv/bin/wapiti"]
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate,os.X_OK):return str(candidate)
        return self.tool("wapiti")

    def wapiti_origin_targets(self) -> list[dict[str,Any]]:
        parameterized=set(self.active_candidates())
        services=[dict(row) for row in self.db.conn.execute("SELECT url,host,status,server,technologies FROM http_services WHERE run_id=? ORDER BY status,url",(self.run_id,))]
        endpoint_rows=self.db.conn.execute("SELECT url,host,query_keys,extension FROM endpoints WHERE run_id=? ORDER BY id DESC LIMIT ?",(self.run_id,self.cfg.max_urls)).fetchall()
        inputs=self.db.conn.execute("SELECT action_url,input_type,name FROM input_points WHERE run_id=?",(self.run_id,)).fetchall()
        by_origin:dict[tuple[str,str,int],dict[str,Any]]={}

        def origin_key(url: str) -> tuple[str,str,int] | None:
            try:
                p=urllib.parse.urlsplit(url);port=p.port or (443 if p.scheme=="https" else 80)
                if p.scheme not in {"http","https"} or not p.hostname:return None
                return p.scheme,p.hostname,port
            except ValueError:return None

        for service in services:
            key=origin_key(str(service["url"]))
            if not key:continue
            p=urllib.parse.urlsplit(str(service["url"]))
            root=urllib.parse.urlunsplit((p.scheme,p.netloc,"/","",""))
            entry=by_origin.setdefault(key,{"base":root,"host":p.hostname,"service":service,"starts":set(),"score":0,"extensions":set(),"inputs":set(),"technologies":set()})
            entry["starts"].add(str(service["url"]));entry["score"]+=3 if int(service.get("status") or 0) in FFUF_VALID_STATUSES else 1
            try:entry["technologies"].update(json.loads(service.get("technologies") or "[]"))
            except json.JSONDecodeError:pass
        for row in endpoint_rows:
            url=str(row["url"]);key=origin_key(url)
            if not key or key not in by_origin:continue
            entry=by_origin[key];entry["starts"].add(url);entry["extensions"].add(str(row["extension"] or "").lower())
            try:keys=json.loads(row["query_keys"] or "[]")
            except json.JSONDecodeError:keys=[]
            if keys:entry["score"]+=5
            if url in parameterized:entry["score"]+=8
        for row in inputs:
            url=str(row["action_url"]);key=origin_key(url)
            if not key or key not in by_origin:continue
            entry=by_origin[key];entry["starts"].add(url);entry["inputs"].add(str(row["input_type"] or "").lower());entry["score"]+=6
        targets=[]
        for entry in by_origin.values():
            starts=sorted(entry["starts"],key=lambda url:(0 if url in parameterized else 1,len(url),url))[:12]
            if starts:targets.append({**entry,"starts":starts})
        return sorted(targets,key=lambda item:(-int(item["score"]),item["base"]))[:max(1,min(5,self.cfg.active_max_urls))]

    def wapiti_modules_for_target(self, target: dict[str,Any]) -> list[str]:
        modules=set(WAPITI_BASE_MODULES)
        starts=set(target.get("starts") or [])
        has_parameters=any("?" in url for url in starts)
        has_inputs=bool(target.get("inputs"))
        if has_parameters or has_inputs:modules.update(WAPITI_PARAMETER_MODULES)
        extensions={str(ext).lower() for ext in target.get("extensions",set())}
        if extensions & {"xml","json"} or has_inputs:modules.update(WAPITI_BODY_MODULES)
        if {"file","upload"} & {str(x).lower() for x in target.get("inputs",set())}:modules.update(WAPITI_UPLOAD_MODULES)
        tech_blob=" ".join(str(x).lower() for x in target.get("technologies",set()))
        if any(word in tech_blob for word in ("java","spring","log4j","tomcat")):modules.update(WAPITI_TECH_MODULES)
        if any(word in tech_blob for word in ("wordpress","drupal","joomla","magento","prestashop","spip","typo3")):modules.add("cms")
        return sorted(modules)

    def wapiti_severity(self, level: Any, bucket: str) -> str:
        try:return WAPITI_LEVELS.get(int(level),"medium" if bucket=="vulnerabilities" else "info")
        except (TypeError,ValueError):return "medium" if bucket=="vulnerabilities" else "info"

    def ingest_wapiti_report(self, path: Path, base_url: str) -> None:
        try:data=json.loads(path.read_text(errors="replace"))
        except (OSError,json.JSONDecodeError):return
        classifications=data.get("classifications",{}) if isinstance(data,dict) else {}
        for bucket,default_tool in (("vulnerabilities","wapiti"),("anomalies","wapiti-anomaly"),("additionals","wapiti-info")):
            groups=data.get(bucket,{}) if isinstance(data,dict) else {}
            if not isinstance(groups,dict):continue
            for category,items in groups.items():
                if not isinstance(items,list):continue
                meta=classifications.get(category,{}) if isinstance(classifications,dict) else {}
                for item in items:
                    if not isinstance(item,dict):continue
                    path_value=str(item.get("path") or item.get("url") or base_url)
                    matched=canonical_url(urllib.parse.urljoin(base_url,path_value),self.cfg.domain) or base_url
                    module=str(item.get("module") or default_tool)
                    info=str(item.get("info") or category or module)
                    parameter=str(item.get("parameter") or "")
                    evidence={"category":category,"module":module,"parameter":parameter,"info":info,"wstg":item.get("wstg"),"curl_command":item.get("curl_command"),"classification":meta}
                    severity=self.wapiti_severity(item.get("level"),bucket)
                    name=f"{category}: {info}" if category and category not in info else info
                    self.db.execute("INSERT OR IGNORE INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,default_tool,severity,f"wapiti:{module}:{category}",name[:500],matched,urllib.parse.urlsplit(matched).hostname or "",json.dumps(evidence,sort_keys=True)[:8000]))

    async def wapiti_checks(self) -> None:
        executable=self.wapiti_executable()
        targets=self.wapiti_origin_targets()
        if not executable or not targets or "wapiti" in self.cfg.skip:
            self.log("11-wapiti: unavailable/no suitable targets/skipped","yellow");self.done+=1;return
        self.log(f"11-wapiti: scanning {len(targets)} prioritized web origin(s) with adaptive modules")
        for idx,target in enumerate(targets):
            modules=self.wapiti_modules_for_target(target)
            report=self.raw/f"wapiti-{idx:03d}.json";session_dir=self.root/"wapiti-sessions"/f"target-{idx:03d}";config_dir=self.root/"wapiti-config";session_dir.mkdir(parents=True,exist_ok=True);config_dir.mkdir(exist_ok=True)
            scan_time=max(120,min(900,self.cfg.timeout*max(8,2+self.cfg.depth)))
            attack_time=max(60,min(300,self.cfg.timeout*4))
            args=["-u",str(target["base"]),"--scope","folder","-m",",".join(modules),"-d",str(min(self.cfg.depth,2)),"--max-scan-time",str(scan_time),"--max-attack-time",str(attack_time),"--max-links-per-page","30","--max-files-per-dir","15","--max-parameters","8","-S","polite","--tasks",str(max(1,min(4,self.cfg.concurrency))),"-t",str(self.cfg.timeout),"-A",self.user_agent("authorized-wapiti-scan"),"--verify-ssl","0","--store-session",str(session_dir),"--store-config",str(config_dir),"--flush-session","--no-bugreport","-f","json","-o",str(report),"-v","0"]
            for start in target["starts"][:10]:
                args += ["-s",str(start)]
            code,_=await self.run_tool("11-wapiti","wapiti",args,timeout=scan_time+attack_time*max(1,len(modules))+120,executable=executable,artifact_name=f"wapiti-{idx:03d}",success_codes={0,1,2})
            if report.exists():self.ingest_wapiti_report(report,str(target["base"]))
            elif code!=0:self.log(f"11-wapiti: no JSON report for {target['base']}","yellow")
            self.db.conn.commit()
        self.done+=1

    def add_tool_finding(self, tool: str, severity: str, name: str, url: str, evidence: str) -> None:
        digest=hashlib.sha256((name+url+evidence).encode(errors="replace")).hexdigest()[:20]
        host=urllib.parse.urlsplit(url).hostname or ""
        self.db.execute("INSERT OR IGNORE INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,tool,severity,digest,name,url,host,evidence[:8000]))

    async def xss_checks(self) -> None:
        candidates=self.active_candidates();targets=self.write_input("active-parameter-urls.txt",candidates)
        if not candidates:self.log("08-xss: no safe parameterized candidates","yellow");self.done+=1;return
        dalfox_env=os.environ.copy();runtime=self.root/"dalfox-runtime";runtime.mkdir()
        dalfox_env.update({"HOME":str(self.root/"dalfox-home"),"XDG_RUNTIME_DIR":str(runtime),"XDG_CACHE_HOME":str(self.root/"dalfox-cache")})
        dalfox_rate=max(1,min(10,round(1/self.cfg.active_delay)))
        code,out=await self.run_tool("08-xss","dalfox",["scan",str(targets),"--format","jsonl","--silence","--no-color","--workers",str(min(2,self.cfg.concurrency)),"--max-concurrent-targets","2","--max-targets-per-host","10","--rate-limit",str(dalfox_rate),"--delay",str(max(100,int(self.cfg.active_delay*1000))),"--timeout",str(self.cfg.timeout),"--scan-timeout","120","--retries","0","--skip-mining","--waf-bypass","off","--skip-waf-probe","--max-payloads-per-param","30"],timeout=3600,env=dalfox_env)
        if code==0:
            for line in out.read_text(errors="replace").splitlines():
                try:
                    row=json.loads(line);joined=json.dumps(row).lower();url=str(row.get("url") or row.get("target") or "")
                    if url and any(x in joined for x in ("verified","vulnerable","xss")):self.add_tool_finding("dalfox","high" if "verified" in joined else "medium","Possible cross-site scripting",url,json.dumps(row))
                except json.JSONDecodeError:continue
        xs=Path(__file__).resolve().parent/"tools/XSStrike/xsstrike.py";isolated=Path(__file__).resolve().parent/"tools/XSStrike/.venv/bin/python";venv=Path(__file__).resolve().parent/"venv/bin/python"
        python=str(isolated if isolated.exists() else (venv if venv.exists() else Path(sys.executable)))
        if xs.exists() and "xsstrike" not in self.cfg.skip:
            for idx,url in enumerate(candidates[:min(10,self.cfg.active_max_urls)]):
                xcode,xout=await self.run_tool("08-xss",f"xsstrike-{idx:03d}",[str(xs),"-u",url,"--skip","--skip-dom","--timeout",str(self.cfg.timeout),"--threads","1","--delay",str(max(1,round(self.cfg.active_delay))),"--console-log-level","GOOD"],timeout=600,executable=python)
                if xcode==0:
                    stderr=self.raw/f"08-xss-xsstrike-{idx:03d}.stderr"
                    output=xout.read_text(errors="replace")+(stderr.read_text(errors="replace") if stderr.exists() else "")
                    lines=[re.sub(r"\x1b\[[0-9;]*m","",x) for x in output.splitlines()]
                    signals=[x.strip() for x in lines if "Payload:" in x or "Vulnerable webpage:" in x]
                    if signals:self.add_tool_finding("xsstrike","medium","Potential XSS vector",url,"\n".join(signals[:20]))
        else:self.log("08-xss: vendored XSStrike unavailable/skipped","yellow")
        self.db.conn.commit();self.done+=1

    async def sqli_checks(self) -> None:
        candidates=self.active_candidates()[:min(10,self.cfg.active_max_urls)]
        script=Path(__file__).resolve().parent/"tools/sqlmap/sqlmap.py";venv=Path(__file__).resolve().parent/"venv/bin/python"
        python=str(venv if venv.exists() else Path(sys.executable))
        if not candidates or not script.exists() or "sqlmap" in self.cfg.skip:
            self.log("09-sqli: no candidates or vendored sqlmap unavailable/skipped","yellow");self.done+=1;return
        for idx,url in enumerate(candidates):
            output_dir=self.raw/f"sqlmap-{idx:03d}"
            args=[str(script),"-u",url,"--batch","--level=1","--risk=1","--technique=BEU","--smart","--threads=1",f"--delay={self.cfg.active_delay}",f"--timeout={self.cfg.timeout}","--retries=0","--skip-static","--disable-coloring",f"--output-dir={output_dir}"]
            code,out=await self.run_tool("09-sqli",f"sqlmap-{idx:03d}",args,timeout=1200,executable=python)
            text=out.read_text(errors="replace") if out.exists() else ""
            if code==0 and ("sqlmap identified the following injection point" in text.lower() or "parameter" in text.lower() and "is vulnerable" in text.lower()):
                evidence="\n".join(x for x in text.splitlines() if any(k in x.lower() for k in ("parameter:","type:","title:","payload:","is vulnerable")))
                self.add_tool_finding("sqlmap","high","Possible SQL injection",url,evidence)
        self.db.conn.commit();self.done+=1

    async def nuclei(self) -> None:
        urls=self.db.values("SELECT url FROM http_services WHERE run_id=?",(self.run_id,)); inp=self.write_input("live-urls.txt",urls)
        executable=self.tool("nuclei")
        update_code,_=await self.run_tool("12-nuclei","nuclei",["-ut","-silent"],timeout=600,executable=executable,artifact_name="nuclei-template-update")
        if update_code==0:
            self.db.execute("INSERT OR IGNORE INTO domain_info(run_id,key,value,source) VALUES(?,?,?,?)",(self.run_id,"Vulnerability templates","Nuclei community templates checked for latest release at "+utcnow(),"nuclei"))
        common=["-l",str(inp),"-jsonl","-silent","-rl",str(self.cfg.rate),"-c",str(min(self.cfg.concurrency,25)),"-timeout",str(self.cfg.timeout),"-retries","1","-or"]
        general=await self.run_tool("12-nuclei","nuclei",common+["-severity","info,low,medium,high,critical"],timeout=7200,executable=executable,artifact_name="nuclei-general")
        technology=await self.run_tool("12-nuclei","nuclei",common+["-as","-severity","low,medium,high,critical"],timeout=7200,executable=executable,artifact_name="nuclei-technology")
        for (code,out),tool_name in ((general,"nuclei"),(technology,"nuclei-tech")):
            if code!=0:continue
            for row in json_lines(out):
                info=row.get("info",{}) or {}; matched=str(row.get("matched-at") or row.get("host") or "")
                host=urllib.parse.urlsplit(matched).hostname or ""
                if host and not self.host_allowed(host):continue
                self.db.execute("INSERT OR IGNORE INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,tool_name,str(info.get("severity","unknown")),str(row.get("template-id") or ""),str(info.get("name") or ""),matched,host,json.dumps(row)))
        self.db.conn.commit();self.done+=1

    async def directories(self) -> None:
        word=self.cfg.wordlist
        if not word:
            base=Path(__file__).resolve().parent
            choices=[base/"wordlists/web-discovery-common.txt",base/"tools/wordlists/SecLists/Discovery/Web-Content/common.txt",base/"tools/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt",Path("/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt"),Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),Path("/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt")]
            word=next((p for p in choices if p.exists()),None)
        rows=self.db.conn.execute("SELECT url FROM http_services WHERE run_id=? AND status BETWEEN 100 AND 599 ORDER BY host,url",(self.run_id,)).fetchall()
        urls=[];seen=set()
        for row in rows:
            url=canonical_url(str(row["url"]),self.cfg.domain)
            if not url:continue
            parsed=urllib.parse.urlsplit(url);origin=urllib.parse.urlunsplit((parsed.scheme,parsed.netloc,"/","",""))
            if origin not in seen:seen.add(origin);urls.append(origin)
        self.log(f"content-discovery: bundled FFUF against all {len(urls)} live in-scope services at {self.cfg.rate} req/s")
        if not word: self.log("08-content: no web discovery wordlist found","yellow"); self.done+=1; return
        if not urls:self.log("08-content: no live web services to enumerate","yellow");self.done+=1;return
        for idx,url in enumerate(urls):
            base=url.rstrip("/")+"/FUZZ"; name=f"ffuf-{idx:03d}"
            args=["-u",base,"-w",str(word),"-json","-s","-noninteractive","-H",f"User-Agent: {self.user_agent('authorized-content-discovery')}","-ac","-ach","-mc","200-299,301,302,307,308,401,403,405","-recursion","-recursion-strategy","default","-recursion-depth",str(self.cfg.depth),"-rate",str(self.cfg.rate),"-t",str(min(self.cfg.concurrency,40)),"-timeout",str(self.cfg.timeout)]
            code,out=await self.run_tool("08-content", "ffuf", args,timeout=max(3600,self.cfg.timeout*20),artifact_name=name)
            for result in json_lines(out):
                try:status=int(result.get("status") or 0)
                except (TypeError,ValueError):continue
                found=canonical_url(str(result.get("url") or ""),self.cfg.domain)
                if found and status in FFUF_VALID_STATUSES:self.add_endpoint(found,"ffuf")
        self.db.conn.commit();self.done+=1

    async def run(self) -> None:
        status="failed"
        try:
            self.seed_scope_assets()
            if self.should_preflight_active_scope() and not await self.preflight_active_scope():
                self.prune_scoped_inventory();self.report();status="complete";self.log("complete: no active scoped hosts found; heavy scan stages skipped","yellow");return
            steps=[
                ("dns","00-domain",self.domain_intelligence),
                ("subdomain_enum","00-recon-ng",self.recon_ng),
                ("subdomain_enum","00-osint",self.additional_osint),
                ("subdomain_enum","01-enumerate",self.enumerate),
            ]
            if self.cfg.profile == "passive":
                steps += [("dns","02-resolve",self.resolve),("dns","02-dns",self.dns_intelligence)]
                self.total=len(steps)
                for stage_key,label,action in steps:await self.run_step(stage_key,label,action)
                self.prune_scoped_inventory();self.report(); status="complete"; self.log(f"complete: {self.root}","green"); return
            if self.cfg.profile=="deep":steps.append(("subdomain_enum","01-archive",self.archive_discovery))
            steps += [
                ("subdomain_enum","01-active-dns",self.active_dns_enumeration),
                ("dns","02-resolve",self.resolve),
                ("dns","02-dns",self.dns_intelligence),
                ("http","04-http",self.probe),
                ("ports","03-ports",self.ports),
                ("http","04-open-ports",self.probe_open_ports),
                ("vulnerabilities","03-takeover",self.takeover_checks),
                ("http","05-crawl",self.crawl),
                ("technologies","06-tech",self.technologies),
            ]
            if self.cfg.profile == "deep":steps.append(("active_checks","09-parameters",self.parameter_discovery))
            steps.append(("content","08-content",self.directories))
            if self.cfg.profile=="deep":steps.append(("http","07-jsminer",self.javascript_analysis))
            steps += [("secrets","07-secrets",self.secrets),("tls","10-tls",self.tls_checks)]
            if self.cfg.profile == "deep":
                steps += [
                    ("active_checks","10-inputs",self.input_checks),
                    ("secrets","08-repos",self.repository_secrets),
                    ("active_checks","11-wapiti",self.wapiti_checks),
                    ("active_checks","08-xss",self.xss_checks),
                    ("active_checks","09-sqli",self.sqli_checks),
                    ("vulnerabilities","12-nuclei",self.nuclei),
                    ("vulnerabilities","18-nikto",self.nikto_checks),
                ]
            self.total=len(steps)
            for stage_key,label,action in steps:await self.run_step(stage_key,label,action)
            self.prune_scoped_inventory();self.report(); status="complete"; self.log(f"complete: {self.root}","green")
        except (KeyboardInterrupt, asyncio.CancelledError):
            status="cancelled"; raise
        finally:
            self.db.finish(self.run_id,status)

    def report(self) -> None:
        c=self.db.conn
        counts={name:c.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?",(self.run_id,)).fetchone()[0] for name,table in {"Domain facts":"domain_info","Assets":"assets","DNS records":"dns_records","Open ports":"ports","Web services":"http_services","Technologies":"technologies","Endpoints":"endpoints","Input points":"input_points","Encoded values":"encoded_artifacts","Repositories":"repositories","Findings":"findings"}.items()}
        services=c.execute("SELECT * FROM http_services WHERE run_id=? ORDER BY host,url",(self.run_id,)).fetchall()
        technologies=c.execute("SELECT * FROM technologies WHERE run_id=? ORDER BY host,category,name,version",(self.run_id,)).fetchall()
        ports=c.execute("SELECT * FROM ports WHERE run_id=? ORDER BY hostname,port",(self.run_id,)).fetchall()
        findings=c.execute("SELECT * FROM findings WHERE run_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",(self.run_id,)).fetchall()
        dns=c.execute("SELECT * FROM dns_records WHERE run_id=? ORDER BY hostname,type,value",(self.run_id,)).fetchall()
        domain_info=c.execute("SELECT * FROM domain_info WHERE run_id=? ORDER BY key,value",(self.run_id,)).fetchall()
        endpoints=c.execute("SELECT * FROM endpoints WHERE run_id=? ORDER BY host,path LIMIT 10000",(self.run_id,)).fetchall()
        repositories=c.execute("SELECT * FROM repositories WHERE run_id=? ORDER BY url",(self.run_id,)).fetchall()
        inputs=c.execute("SELECT * FROM input_points WHERE run_id=? ORDER BY page_url,name",(self.run_id,)).fetchall()
        encoded=c.execute("SELECT * FROM encoded_artifacts WHERE run_id=? ORDER BY source_url,location",(self.run_id,)).fetchall()
        tool_runs=c.execute("SELECT tool,stage,status,ROUND(duration,2) duration,exit_code FROM tool_runs WHERE run_id=? ORDER BY id",(self.run_id,)).fetchall()
        def esc(x:Any)->str:return html.escape(str(x or ""))
        cards="".join(f'<div class="card"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k,v in counts.items())
        def table(headers:list[str],rows:Iterable[Iterable[Any]])->str:
            return '<div class="table"><table><thead><tr>'+''.join(f'<th>{esc(h)}</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{esc(x)}</td>' for x in row)+'</tr>' for row in rows)+'</tbody></table></div>'
        def links(rows:Iterable[sqlite3.Row])->str:
            return '<div class="links">'+''.join(f'<div><a href="{esc(redact_url(r["url"]))}">{esc(redact_url(r["url"]))}</a><span>{esc(r["source"])} · {esc(r["query_keys"])}</span></div>' for r in rows)+'</div>'
        js=[r for r in endpoints if r["extension"] in {"js","mjs","map","json"}]
        parameterized=[r for r in endpoints if r["query_keys"]!="[]" and r not in js]
        other=[r for r in endpoints if r not in js and r not in parameterized]
        doc=f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{esc(self.cfg.domain)} Recon Report</title><style>
        :root{{--bg:#08111d;--panel:#101e2e;--line:#233950;--text:#e8f0f8;--muted:#8da5b9;--accent:#28d7b7}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px system-ui}}main{{max-width:1400px;margin:auto;padding:32px}}h1{{font-size:34px;margin-bottom:5px}}h2{{margin-top:34px}}h3{{color:#b8cce0;margin-top:24px}}a{{color:#68e6cf}}.muted{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:28px 0}}.card{{padding:18px;background:linear-gradient(145deg,#122438,#0d1927);border:1px solid var(--line);border-radius:12px}}.card b{{display:block;font-size:27px;color:var(--accent)}}.card span{{color:var(--muted)}}.table{{overflow:auto;border:1px solid var(--line);border-radius:10px}}table{{border-collapse:collapse;width:100%;background:var(--panel)}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}tr:nth-child(even),.links>div:nth-child(even){{background:#0d1a28}}th{{position:sticky;top:0;background:#16293d;color:var(--accent)}}.links{{border:1px solid var(--line);border-radius:10px;overflow:hidden}}.links>div{{display:flex;gap:15px;justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}.links span{{color:var(--muted);white-space:nowrap}}code{{color:#9ce9dc}} </style></head><body><main><div class="muted">AUTHORIZED ATTACK-SURFACE INVENTORY · {esc(utcnow())}</div><h1>{esc(self.cfg.domain)}</h1><div class="muted">Profile: {esc(self.cfg.profile)} · Pipeline {VERSION}</div><div class="cards">{cards}</div>
        <h2>HTTP services</h2>{table(['URL','Status','Title','Server','Technologies'],((redact_url(r['url']),r['status'],r['title'],r['server'],r['technologies']) for r in services))}
        <h2>Technology versions</h2>{table(['Host','URL','Name','Version','Category','Source','Confidence','Evidence'],((r['host'],redact_url(r['url']),r['name'],r['version'],r['category'],r['source'],r['confidence'],r['evidence']) for r in technologies))}
        <h2>Domain registration and ownership</h2>{table(['Field','Value','Source'],((r['key'],r['value'],r['source']) for r in domain_info))}
        <h2>DNS records</h2>{table(['Host','Type','Value','Source'],((r['hostname'],r['type'],r['value'],r['source']) for r in dns))}
        <h2>Open ports</h2>{table(['Host','IP','Port','Protocol','Service'],((r['hostname'],r['ip'],r['port'],r['protocol'],r['service']) for r in ports))}
        <h2>Scanner observations</h2>{table(['Severity','Name','Template','Matched at'],((r['severity'],r['name'],r['template_id'],redact_url(r['matched_at'])) for r in findings))}
        <h2>Tool execution ledger</h2>{table(['Tool','Stage','Status','Seconds','Exit'],((r['tool'],r['stage'],r['status'],r['duration'],r['exit_code']) for r in tool_runs))}
        <h2>Discovered repositories</h2>{table(['Repository','Source','Secret scanned'],((r['url'],r['source'],'yes' if r['scanned'] else 'no') for r in repositories))}
        <h2>Input surface</h2>{table(['Page','Action','Method','Field','Type','Tested','Reflection'],((r['page_url'],r['action_url'],r['method'],r['name'],r['input_type'],'yes' if r['tested'] else 'no',r['reflection_context']) for r in inputs))}
        <h2>Encoded and hashed values</h2>{table(['Source','Location','Type','Value preview','Decoded analysis','Hash'],((r['source_url'],r['location'],r['kind'],r['value_preview'],r['decoded_preview'],'yes' if r['is_hash'] else 'no') for r in encoded))}
        <h2>Discovered endpoints</h2><h3>JavaScript, source maps and structured data</h3>{links(js)}<h3>Parameterized entry points</h3>{links(parameterized)}<h3>Other in-scope links</h3>{links(other)}
        <p class="muted">Raw evidence and the complete SQLite database are stored beside this report. Scanner matches require manual validation.</p></main></body></html>"""
        (self.root/"report.html").write_text(doc); (self.root/"summary.json").write_text(json.dumps({"domain":self.cfg.domain,"run_id":self.run_id,"counts":counts,"generated_at":utcnow()},indent=2))


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description="Scope-safe reconnaissance orchestrator for authorized testing")
    p.add_argument("domain",nargs="?",help="authorized apex domain, or a text file containing one domain per line")
    p.add_argument("--targets-file",type=Path,help="scan multiple authorized apex domains sequentially with isolated reports")
    p.add_argument("--i-have-authorization",action="store_true",help="required acknowledgement of written authorization")
    p.add_argument("--profile",choices=["passive","standard","deep"],default="standard")
    p.add_argument("--output",type=Path,default=Path("results"));p.add_argument("--rate",type=int,default=50);p.add_argument("--concurrency",type=int,default=30)
    p.add_argument("--timeout",type=int,default=10);p.add_argument("--depth",type=int,default=3);p.add_argument("--max-urls",type=int,default=5000)
    p.add_argument("--wordlist",type=Path);p.add_argument("--screenshots",action="store_true");p.add_argument("--skip",default="",help="comma-separated tool names")
    p.add_argument("--skip-stages",default="",help="comma-separated stage groups to skip: subdomain_enum,dns,http,ports,content,technologies,secrets,tls,active_checks,vulnerabilities")
    p.add_argument("--scope-subdomains",default="",help="comma/space/newline-separated in-scope hostnames to scan without discovering more")
    p.add_argument("--scope-subdomains-file",type=Path,help="file containing in-scope hostnames to seed into the scan")
    p.add_argument("--user-agent-file",type=Path,help="file containing one User-Agent per line; defaults to ./user-agent.txt when present")
    p.add_argument("--secret-max-files",type=int,default=2000,help="maximum in-scope text resources inspected for exposures")
    p.add_argument("--secret-max-bytes",type=int,default=2_000_000,help="maximum bytes read from each resource")
    p.add_argument("--active-max-urls",type=int,default=25,help="maximum deduplicated parameterized URLs for deep active checks")
    p.add_argument("--active-delay",type=float,default=0.5,help="minimum delay in seconds for deep active scanners")
    p.add_argument("--repo-max",type=int,default=3,help="maximum linked GitHub repositories scanned per target")
    p.add_argument("--version",action="version",version=VERSION); return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    if not args.i_have_authorization:
        print("Refusing to scan: add --i-have-authorization only when you have explicit written permission.",file=sys.stderr);return 2
    target_file=args.targets_file
    if not target_file and args.domain and Path(args.domain).is_file():target_file=Path(args.domain)
    try:raw_targets=target_file.read_text(errors="replace").splitlines() if target_file else ([args.domain] if args.domain else [])
    except OSError as exc:print(f"error: cannot read targets file: {exc}",file=sys.stderr);return 2
    domains=[]
    try:
        for value in raw_targets:
            value=value.strip()
            if value and not value.startswith("#"):domains.append(canonical_domain(value))
    except ValueError as exc: print(f"error: {exc}",file=sys.stderr);return 2
    domains=list(dict.fromkeys(domains))
    if not domains:print("error: provide a domain or non-empty --targets-file",file=sys.stderr);return 2
    if not (1<=args.rate<=1000 and 1<=args.concurrency<=500 and 1<=args.timeout<=120 and 1<=args.depth<=10 and 10<=args.max_urls<=1_000_000 and 1<=args.secret_max_files<=100_000 and 1024<=args.secret_max_bytes<=20_000_000 and 1<=args.active_max_urls<=500 and 0.1<=args.active_delay<=30 and 0<=args.repo_max<=25):
        print("error: numeric option outside safe range",file=sys.stderr);return 2
    if args.wordlist and not args.wordlist.is_file(): print("error: wordlist does not exist",file=sys.stderr);return 2
    if args.scope_subdomains_file and not args.scope_subdomains_file.is_file(): print("error: scope subdomains file does not exist",file=sys.stderr);return 2
    if args.user_agent_file and not args.user_agent_file.is_file(): print("error: user agent file does not exist",file=sys.stderr);return 2
    try:
        skip_stages=parse_stage_skips(args.skip_stages)
        for index,domain in enumerate(domains,1):
            if len(domains)>1:print(f"\n=== Target {index}/{len(domains)}: {domain} ===",file=sys.stderr,flush=True)
            raw_scope=args.scope_subdomains
            if args.scope_subdomains_file:raw_scope += "\n" + args.scope_subdomains_file.read_text(errors="replace")
            scope=tuple(dict.fromkeys(canonical_scope_subdomain(value,domain) for value in re.split(r"[\s,]+",raw_scope) if value.strip()))
            cfg=Config(domain,args.profile,args.output.resolve(),args.rate,args.concurrency,args.timeout,args.depth,args.max_urls,args.wordlist.resolve() if args.wordlist else None,args.screenshots,{x.strip().lower() for x in args.skip.split(",") if x.strip()},args.secret_max_files,args.secret_max_bytes,args.active_max_urls,args.active_delay,args.repo_max,skip_stages,scope,args.user_agent_file.resolve() if args.user_agent_file else None)
            asyncio.run(Pipeline(cfg).run())
        return 0
    except ValueError as exc: print(f"error: {exc}",file=sys.stderr);return 2
    except KeyboardInterrupt: print("scan interrupted; partial results were preserved",file=sys.stderr);return 130


if __name__ == "__main__": raise SystemExit(main())
