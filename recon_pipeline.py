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
import ipaddress
import json
import math
import os
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
from pathlib import Path
from typing import Any, Iterable

VERSION = "2.0.0"
DOMAIN_RE = re.compile(r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
SECRET_QUERY_KEYS = {"access_token", "api_key", "apikey", "auth", "authorization", "client_secret", "key", "password", "secret", "sig", "signature", "token"}
SKIP_FETCH_EXTENSIONS = {"7z","avi","avif","bmp","css","eot","flac","gif","gz","ico","jpeg","jpg","m4a","mov","mp3","mp4","mpeg","otf","pdf","png","rar","svg","tar","ttf","wav","webm","webp","woff","woff2","zip"}
ANSI = {"cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m", "dim": "\033[2m", "reset": "\033[0m"}


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


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, domain TEXT, profile TEXT, started_at TEXT, finished_at TEXT, status TEXT, config_json TEXT);
        CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, run_id INTEGER, hostname TEXT, source TEXT, resolved INTEGER DEFAULT 0, first_seen TEXT, UNIQUE(run_id,hostname), FOREIGN KEY(run_id) REFERENCES runs(id));
        CREATE TABLE IF NOT EXISTS dns_records(id INTEGER PRIMARY KEY, run_id INTEGER, hostname TEXT, type TEXT, value TEXT, source TEXT, UNIQUE(run_id,hostname,type,value));
        CREATE TABLE IF NOT EXISTS ports(id INTEGER PRIMARY KEY, run_id INTEGER, hostname TEXT, ip TEXT, port INTEGER, protocol TEXT, service TEXT, source TEXT, UNIQUE(run_id,hostname,ip,port,protocol));
        CREATE TABLE IF NOT EXISTS http_services(id INTEGER PRIMARY KEY, run_id INTEGER, url TEXT, host TEXT, status INTEGER, title TEXT, server TEXT, technologies TEXT, content_type TEXT, content_length INTEGER, ip TEXT, final_url TEXT, raw_json TEXT, UNIQUE(run_id,url));
        CREATE TABLE IF NOT EXISTS endpoints(id INTEGER PRIMARY KEY, run_id INTEGER, url TEXT, host TEXT, path TEXT, query_keys TEXT, extension TEXT, source TEXT, first_seen TEXT, UNIQUE(run_id,url));
        CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, run_id INTEGER, tool TEXT, severity TEXT, template_id TEXT, name TEXT, matched_at TEXT, host TEXT, evidence TEXT, UNIQUE(run_id,tool,template_id,matched_at));
        CREATE TABLE IF NOT EXISTS domain_info(id INTEGER PRIMARY KEY, run_id INTEGER, key TEXT, value TEXT, source TEXT, UNIQUE(run_id,key,value,source));
        CREATE TABLE IF NOT EXISTS repositories(id INTEGER PRIMARY KEY, run_id INTEGER, url TEXT, host TEXT, source TEXT, scanned INTEGER DEFAULT 0, UNIQUE(run_id,url));
        CREATE TABLE IF NOT EXISTS tool_runs(id INTEGER PRIMARY KEY, run_id INTEGER, stage TEXT, tool TEXT, command_json TEXT, started_at TEXT, duration REAL, exit_code INTEGER, status TEXT, stdout_path TEXT, stderr_path TEXT);
        CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(run_id,hostname); CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(run_id,host);
        """)
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


class Pipeline:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.root = cfg.output / f"{cfg.domain}-{stamp}"
        self.raw = self.root / "raw"; self.inputs = self.root / "inputs"
        self.raw.mkdir(parents=True); self.inputs.mkdir()
        self.db = Database(self.root / "recon.sqlite3")
        self.run_id = self.db.start(cfg.domain, cfg.profile, dataclasses.asdict(cfg) | {"output": str(cfg.output), "wordlist": str(cfg.wordlist) if cfg.wordlist else None, "skip": sorted(cfg.skip)})
        self.done = 0; self.total = 19 if cfg.profile == "deep" else (5 if cfg.profile == "passive" else 12)
        self.pipeline_started=time.monotonic()

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
            local = Path(__file__).resolve().parent / "tools" / "bin" / name
            if local.is_file() and os.access(local, os.X_OK):
                return str(local)
            found = shutil.which(name)
            if found:
                return found
        return None

    async def run_tool(self, stage: str, name: str, args: list[str], timeout: int | None = None, stdin: Path | None = None, executable: str | None = None, env: dict[str,str] | None = None, cwd: Path | None = None) -> tuple[int, Path]:
        exe = executable or self.tool(name)
        out = self.raw / f"{stage}-{name}.stdout"; err = self.raw / f"{stage}-{name}.stderr"
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
                status = "ok" if code == 0 else "failed"
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
            request=urllib.request.Request("https://rdap.org/domain/"+urllib.parse.quote(self.cfg.domain),headers={"Accept":"application/rdap+json, application/json","User-Agent":f"ReconPipeline/{VERSION} authorized-security-review"})
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
                    if in_scope_host(host,self.cfg.domain) and DOMAIN_RE.fullmatch(host):
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
                    self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host.lower(),"theHarvester",utcnow()))
                for email in set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",text)):
                    self.db.execute("INSERT OR IGNORE INTO domain_info(run_id,key,value,source) VALUES(?,?,?,?)",(self.run_id,"Public email",email,"theHarvester"))
        spider=base/"tools/spiderfoot/sf.py";spython=base/"tools/spiderfoot/.venv/bin/python"
        if spider.exists() and spython.exists() and "spiderfoot" not in self.cfg.skip:
            shome=self.root/"spiderfoot-home";shome.mkdir();senv=os.environ.copy();senv["HOME"]=str(shome)
            code,out=await self.run_tool("00-osint","spiderfoot",[str(spider),"-s",self.cfg.domain,"-u","passive","-o","json","-q","-max-threads","3"],timeout=900,executable=str(spython),cwd=spider.parent,env=senv)
            if code==0:
                text=out.read_text(errors="replace")
                for host in set(re.findall(rf"(?i)\b(?:[a-z0-9-]+\.)+{re.escape(self.cfg.domain)}\b",text)):
                    self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(self.run_id,host.lower(),"spiderfoot",utcnow()))
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
            if in_scope_host(host, self.cfg.domain) and DOMAIN_RE.fullmatch(host):
                self.db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)", (self.run_id,host,"ducky-subs",utcnow()))
        self.db.conn.commit(); self.done += 1

    async def resolve(self) -> None:
        hosts = self.db.values("SELECT hostname FROM assets WHERE run_id=?", (self.run_id,)); inp = self.write_input("hosts.txt", hosts)
        code, out = await self.run_tool("02-resolve", "dnsx", ["-l", str(inp), "-a", "-aaaa", "-cname", "-resp", "-json", "-silent", "-rl", str(self.cfg.rate), "-t", str(self.cfg.concurrency)])
        if code == 0:
            for row in json_lines(out):
                host = str(row.get("host") or row.get("input") or "").lower()
                if not in_scope_host(host,self.cfg.domain): continue
                values = row.get("a", []) + row.get("aaaa", []) + row.get("cname", [])
                for value in values:
                    typ = "AAAA" if ":" in str(value) else ("A" if re.fullmatch(r"[\d.]+",str(value)) else "CNAME")
                    self.db.execute("INSERT OR IGNORE INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)", (self.run_id,host,typ,str(value),"dnsx"))
                if values: self.db.execute("UPDATE assets SET resolved=1 WHERE run_id=? AND hostname=?",(self.run_id,host))
        self.db.conn.commit(); self.done += 1

    async def takeover_checks(self) -> None:
        hosts=self.db.values("SELECT hostname FROM assets WHERE run_id=?",(self.run_id,));inp=self.write_input("all-subdomains.txt",hosts)
        self.log(f"03-takeover: checking {len(hosts)} discovered hosts")
        base=Path(__file__).resolve().parent;subover=self.tool("subover");subout=self.raw/"takeover-subover.txt"
        if subover and "subover" not in self.cfg.skip:
            source=base/"tools/SubOver"
            code,out=await self.run_tool("03-takeover","subover",["-l",str(inp),"-o",str(subout),"-t",str(min(10,self.cfg.concurrency)),"-timeout",str(self.cfg.timeout)],timeout=1800,executable=subover,cwd=source if source.exists() else base)
            evidence=(subout.read_text(errors="replace") if subout.exists() else out.read_text(errors="replace"))
            for line in evidence.splitlines():
                if any(word in line.lower() for word in ("vulnerable","takeover","can be claimed")):
                    host=next((h for h in hosts if h in line),self.cfg.domain);self.add_tool_finding("subover","high","Potential subdomain takeover",f"https://{host}/",line)
        if self.tool("nuclei") and "nuclei" not in self.cfg.skip:
            code,out=await self.run_tool("03-takeover","nuclei-takeover",["-l",str(inp),"-tags","takeover","-jsonl","-silent","-rl",str(min(self.cfg.rate,25)),"-c",str(min(self.cfg.concurrency,10)),"-timeout",str(self.cfg.timeout),"-retries","1","-or"],timeout=1800,executable=self.tool("nuclei"))
            for row in json_lines(out):
                info=row.get("info",{}) or {};matched=str(row.get("matched-at") or row.get("host") or "")
                host=urllib.parse.urlsplit(matched).hostname or matched.split(":")[0]
                if in_scope_host(host,self.cfg.domain):self.add_tool_finding("nuclei-takeover",str(info.get("severity") or "high"),str(info.get("name") or "Potential subdomain takeover"),matched,json.dumps(row))
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
        if open_ports and self.tool("nmap") and "nmap" not in self.cfg.skip:
            nmap_out=self.raw/"03-ports-nmap.xml"
            ncode,nstdout=await self.run_tool("03-services","nmap",["-Pn","-n","-sV","--version-light","-T3","--host-timeout","10m","-p",",".join(map(str,open_ports)),"-iL",str(inp),"-oX","-"],timeout=3600)
            if ncode==0:
                nmap_out.write_bytes(nstdout.read_bytes())
                try:
                    root=ET.parse(nstdout).getroot()
                    for host_node in root.findall("host"):
                        addr_node=host_node.find("address[@addrtype='ipv4']")
                        if addr_node is None: addr_node=host_node.find("address")
                        ip=addr_node.get("addr","") if addr_node is not None else ""
                        for port_node in host_node.findall("./ports/port"):
                            service=port_node.find("service"); parts=[]
                            if service is not None:
                                parts=[service.get(k,"") for k in ("name","product","version","extrainfo")]
                            label=" ".join(x for x in parts if x)
                            self.db.execute("UPDATE ports SET service=?,source='naabu+nmap' WHERE run_id=? AND ip=? AND port=?",(label,self.run_id,ip,int(port_node.get("portid","0"))))
                except ET.ParseError:
                    self.log("03-services: could not parse nmap XML; raw output preserved","yellow")
        self.db.conn.commit(); self.done+=1

    async def probe(self) -> None:
        hosts=self.db.values("SELECT hostname FROM assets WHERE run_id=? AND resolved=1",(self.run_id,)); inp=self.write_input("http-targets.txt",hosts)
        args=["-l",str(inp),"-json","-silent","-sc","-title","-server","-td","-ct","-cl","-ip","-location","-fr","-rl",str(self.cfg.rate),"-t",str(self.cfg.concurrency),"-timeout",str(self.cfg.timeout)]
        if self.cfg.screenshots:
            args += ["-ss", "-esb", "-ehb", "-srd", str(self.raw / "screenshots")]
        code,out=await self.run_tool("04-http","httpx",args,timeout=3600)
        if code==0:
            for row in json_lines(out):
                url=canonical_url(str(row.get("url") or row.get("input") or ""),self.cfg.domain)
                if not url: continue
                p=urllib.parse.urlsplit(url); tech=row.get("tech",[])
                self.db.execute("INSERT OR REPLACE INTO http_services(run_id,url,host,status,title,server,technologies,content_type,content_length,ip,final_url,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(self.run_id,url,p.hostname,int(row.get("status_code") or 0),str(row.get("title") or ""),str(row.get("webserver") or ""),json.dumps(tech),str(row.get("content_type") or ""),int(row.get("content_length") or 0),str(row.get("host_ip") or row.get("ip") or ""),str(row.get("final_url") or row.get("location") or ""),json.dumps(row)))
                self.add_endpoint(url,"httpx")
        self.db.conn.commit(); self.done+=1

    def add_endpoint(self, url: str, source: str) -> None:
        current=self.db.conn.execute("SELECT COUNT(*) FROM endpoints WHERE run_id=?",(self.run_id,)).fetchone()[0]
        if current >= self.cfg.max_urls:return
        url=canonical_url(url,self.cfg.domain)
        if not url:return
        p=urllib.parse.urlsplit(url); keys=sorted({k for k,_ in urllib.parse.parse_qsl(p.query,keep_blank_values=True)}); ext=Path(p.path).suffix.lower().lstrip(".")
        self.db.execute("INSERT OR IGNORE INTO endpoints(run_id,url,host,path,query_keys,extension,source,first_seen) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,url,p.hostname,p.path,json.dumps(keys),ext,source,utcnow()))

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
        jobs=[self.run_tool("05-crawl","katana",["-list",str(inp),"-jsonl","-silent","-jc","-kf","all","-fx","-d",str(self.cfg.depth),"-rl",str(self.cfg.rate),"-c",str(min(self.cfg.concurrency,20)),"-p","5","-mdp",str(max(10,self.cfg.max_urls//max(1,len(urls)))),"-fs","rdn","-do"],timeout=3600)]
        if self.tool("gau"): jobs.append(self.run_tool("05-archive","gau",["--subs",self.cfg.domain],timeout=1800))
        if self.tool("waybackurls"): jobs.append(self.run_tool("05-wayback","waybackurls",[],timeout=1800,stdin=self.write_input("apex.txt",[self.cfg.domain])))
        results=await asyncio.gather(*jobs)
        for (_,path),source in zip(results,["katana","gau","waybackurls"]):
            for line in path.read_text(errors="replace").splitlines() if path.exists() else []:
                if line.startswith("{"):
                    try:
                        row=json.loads(line); line=str(row.get("request",{}).get("endpoint") or row.get("url") or "")
                    except json.JSONDecodeError: continue
                for found in URL_RE.findall(line):self.add_repository(found,source);self.add_endpoint(found,source)
                if line.startswith("http"): self.add_endpoint(line,source)
        self.db.conn.execute("DELETE FROM endpoints WHERE id NOT IN (SELECT MIN(id) FROM endpoints WHERE run_id=? GROUP BY url) AND run_id=?",(self.run_id,self.run_id)); self.db.conn.commit(); self.done+=1

    async def technologies(self) -> None:
        urls=self.db.values("SELECT url FROM http_services WHERE run_id=?",(self.run_id,)); inp=self.write_input("live-urls.txt",urls)
        await self.run_tool("06-tech","whatweb",["--log-json="+str(self.raw/"whatweb.json"),"--no-errors","--aggression=1","--input-file="+str(inp)],timeout=1800)
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
        request=urllib.request.Request(url,headers={"User-Agent":f"ReconPipeline/{VERSION} authorized-security-review","Accept":"text/html,application/javascript,application/json,text/plain,application/xml;q=0.9,*/*;q=0.1","Accept-Encoding":"identity"})
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
            _,mantra_out=await self.run_tool("07-secrets","mantra",["-s","-t",str(min(5,self.cfg.concurrency)),"-ua",f"ReconPipeline/{VERSION}"],timeout=1800,stdin=mantra_input,executable=mantra)
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
        urls=self.db.values("SELECT url FROM http_services WHERE run_id=? ORDER BY url LIMIT 5",(self.run_id,));nikto=self.tool("nikto")
        if not urls or not nikto or "nikto" in self.cfg.skip:self.log("18-nikto: unavailable/no targets/skipped","yellow");self.done+=1;return
        for idx,url in enumerate(urls):
            report=self.raw/f"nikto-{idx:03d}.xml"
            await self.run_tool("18-nikto",f"nikto-{idx:03d}",["-host",url,"-nointeractive","-ask","no","-Pause",str(self.cfg.active_delay),"-maxtime","5m","-timeout",str(self.cfg.timeout),"-Tuning","123b","-Format","xml","-output",str(report)],timeout=600,executable=nikto)
            if report.exists():
                try:root=ET.parse(report).getroot()
                except ET.ParseError:continue
                for item in root.findall(".//item"):
                    desc=" ".join((item.findtext("description") or "").split());uri=item.findtext("uri") or url
                    if desc:self.add_tool_finding("nikto","info","Nikto observation",urllib.parse.urljoin(url,uri),desc)
        self.db.conn.commit();self.done+=1

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
        code,out=await self.run_tool("07-nuclei","nuclei",["-l",str(inp),"-jsonl","-silent","-severity","info,low,medium,high,critical","-rl",str(self.cfg.rate),"-c",str(min(self.cfg.concurrency,25)),"-timeout",str(self.cfg.timeout),"-retries","1","-or"],timeout=7200)
        if code==0:
            for row in json_lines(out):
                info=row.get("info",{}) or {}; matched=str(row.get("matched-at") or row.get("host") or "")
                host=urllib.parse.urlsplit(matched).hostname or ""
                if host and not in_scope_host(host,self.cfg.domain):continue
                self.db.execute("INSERT OR IGNORE INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(self.run_id,"nuclei",str(info.get("severity","unknown")),str(row.get("template-id") or ""),str(info.get("name") or ""),matched,host,json.dumps(row)))
        self.db.conn.commit();self.done+=1

    async def directories(self) -> None:
        word=self.cfg.wordlist
        if not word:
            choices=[Path("/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt"),Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),Path("/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt")]
            word=next((p for p in choices if p.exists()),None)
        urls=self.db.values("SELECT url FROM http_services WHERE run_id=? ORDER BY url LIMIT 25",(self.run_id,))
        self.log(f"content-discovery: FFUF against {len(urls)} live services")
        if not word: self.log("08-content: no SecLists web wordlist found","yellow"); self.done+=1; return
        for idx,url in enumerate(urls):
            base=url.rstrip("/")+"/FUZZ"; name=f"ffuf-{idx:03d}"
            code,out=await self.run_tool("08-content", "ffuf", ["-u",base,"-w",str(word),"-json","-s","-ac","-ach","-recursion","-recursion-depth","1","-rate",str(self.cfg.rate),"-t",str(min(self.cfg.concurrency,40)),"-timeout",str(self.cfg.timeout),"-maxtime","300"])
            if code==0:
                for row in json_lines(out): self.add_endpoint(str(row.get("url") or ""),"ffuf")
        self.db.conn.commit();self.done+=1

    async def run(self) -> None:
        status="failed"
        try:
            await self.domain_intelligence();await self.recon_ng();await self.additional_osint();await self.enumerate(); await self.resolve();await self.dns_intelligence()
            if self.cfg.profile == "passive":
                self.report(); status="complete"; self.log(f"complete: {self.root}","green"); return
            await self.takeover_checks();await self.ports()
            await self.probe(); await self.crawl(); await self.technologies()
            if self.cfg.profile == "deep":await self.parameter_discovery();await self.directories()
            await self.secrets();await self.tls_checks()
            if self.cfg.profile == "deep":await self.repository_secrets();await self.xss_checks();await self.sqli_checks();await self.nuclei();await self.nikto_checks()
            self.report(); status="complete"; self.log(f"complete: {self.root}","green")
        except (KeyboardInterrupt, asyncio.CancelledError):
            status="cancelled"; raise
        finally:
            self.db.finish(self.run_id,status)

    def report(self) -> None:
        c=self.db.conn
        counts={name:c.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?",(self.run_id,)).fetchone()[0] for name,table in {"Domain facts":"domain_info","Assets":"assets","DNS records":"dns_records","Open ports":"ports","Web services":"http_services","Endpoints":"endpoints","Repositories":"repositories","Findings":"findings"}.items()}
        services=c.execute("SELECT * FROM http_services WHERE run_id=? ORDER BY host,url",(self.run_id,)).fetchall()
        ports=c.execute("SELECT * FROM ports WHERE run_id=? ORDER BY hostname,port",(self.run_id,)).fetchall()
        findings=c.execute("SELECT * FROM findings WHERE run_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",(self.run_id,)).fetchall()
        dns=c.execute("SELECT * FROM dns_records WHERE run_id=? ORDER BY hostname,type,value",(self.run_id,)).fetchall()
        domain_info=c.execute("SELECT * FROM domain_info WHERE run_id=? ORDER BY key,value",(self.run_id,)).fetchall()
        endpoints=c.execute("SELECT * FROM endpoints WHERE run_id=? ORDER BY host,path LIMIT 10000",(self.run_id,)).fetchall()
        repositories=c.execute("SELECT * FROM repositories WHERE run_id=? ORDER BY url",(self.run_id,)).fetchall()
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
        <h2>Domain registration and ownership</h2>{table(['Field','Value','Source'],((r['key'],r['value'],r['source']) for r in domain_info))}
        <h2>DNS records</h2>{table(['Host','Type','Value','Source'],((r['hostname'],r['type'],r['value'],r['source']) for r in dns))}
        <h2>Open ports</h2>{table(['Host','IP','Port','Protocol','Service'],((r['hostname'],r['ip'],r['port'],r['protocol'],r['service']) for r in ports))}
        <h2>Scanner observations</h2>{table(['Severity','Name','Template','Matched at'],((r['severity'],r['name'],r['template_id'],redact_url(r['matched_at'])) for r in findings))}
        <h2>Tool execution ledger</h2>{table(['Tool','Stage','Status','Seconds','Exit'],((r['tool'],r['stage'],r['status'],r['duration'],r['exit_code']) for r in tool_runs))}
        <h2>Discovered repositories</h2>{table(['Repository','Source','Secret scanned'],((r['url'],r['source'],'yes' if r['scanned'] else 'no') for r in repositories))}
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
    try:
        for index,domain in enumerate(domains,1):
            if len(domains)>1:print(f"\n=== Target {index}/{len(domains)}: {domain} ===",file=sys.stderr,flush=True)
            cfg=Config(domain,args.profile,args.output.resolve(),args.rate,args.concurrency,args.timeout,args.depth,args.max_urls,args.wordlist.resolve() if args.wordlist else None,args.screenshots,{x.strip().lower() for x in args.skip.split(",") if x.strip()},args.secret_max_files,args.secret_max_bytes,args.active_max_urls,args.active_delay,args.repo_max)
            asyncio.run(Pipeline(cfg).run())
        return 0
    except KeyboardInterrupt: print("scan interrupted; partial results were preserved",file=sys.stderr);return 130


if __name__ == "__main__": raise SystemExit(main())
