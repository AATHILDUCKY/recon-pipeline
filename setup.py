#!/usr/bin/env python3
"""Idempotent development bootstrap for Recon Pipeline.

Run ``python3 setup.py`` after cloning. This intentionally never deletes scan
results, runtime databases, configuration, or existing tool checkouts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
BIN = TOOLS / "bin"
VENV = ROOT / "venv"
WORDLISTS = TOOLS / "wordlists"

# Revisions tested with Recon Pipeline 2.0. Updating is an explicit operation.
REPOSITORIES = {
    "SubOver": ("https://github.com/Ice3man543/SubOver.git", "3d258e254ab5b5f37ec6fc2dcd55b45f266ac5f6"),
    "XSStrike": ("https://github.com/s0md3v/XSStrike.git", "ab27955d367432f944d8f29897e09c15356e76f7"),
    "dnsenum": ("https://github.com/fwaeytens/dnsenum.git", "e3336c51a6d43d1ebb292970958e9cdc0cf93419"),
    "gitleaks": ("https://github.com/gitleaks/gitleaks.git", "8ad8470035d31a209322c580153b45c18e21b980"),
    "mantra": ("https://github.com/Brosck/mantra.git", "6026816210df756f8cc8e9d637b9f49fb277a5f0"),
    "recon-ng": ("https://github.com/lanmaster53/recon-ng.git", "c08acee0f84645ecf521ec616ac2dde94cbc1d63"),
    "recon-ng-marketplace": ("https://github.com/lanmaster53/recon-ng-marketplace.git", "9527714d2bb38886422bab5f1c4724d4a20d3057"),
    "spiderfoot": ("https://github.com/smicallef/spiderfoot.git", "0f815a203afebf05c98b605dba5cf0475a0ee5fd"),
    "sqlmap": ("https://github.com/sqlmapproject/sqlmap.git", "e1aac02ef2ca017e2dc5f4be8883db59d039295a"),
    "testssl.sh": ("https://github.com/testssl/testssl.sh.git", "b5a83f5f1087389ca2fd7b2872b8cbf438d05f91"),
    "theHarvester": ("https://github.com/laramies/theHarvester.git", "14d9f2999657f3285de78e5c42c66b626e84c2a1"),
    "trufflehog": ("https://github.com/trufflesecurity/trufflehog.git", "9b6b5326bfe25dbd856eccc8a8275eb5dea7bd52"),
}

GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@v1.6.1",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0",
    "gau": "github.com/lc/gau/v2/cmd/gau@v2.2.4",
    "waybackurls": "github.com/tomnomnom/waybackurls@v0.1.0",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "gobuster": "github.com/OJ/gobuster/v3@v3.8.2",
    "jsminer": "github.com/tavgar/JSMiner/cmd/jsminer@latest",
    "subjack": "github.com/haccer/subjack@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
}

OS_COMMANDS = ("git", "go", "nmap", "whatweb", "whois", "dig", "sslscan", "nikto", "perl")
STAMP_NAME = ".recon-pipeline-install.json"
SOURCE_BINARIES = {"SubOver": "subover", "gitleaks": "gitleaks", "mantra": "mantra", "trufflehog": "trufflehog"}
WORDLIST_REPOSITORIES = {
    "SecLists": "https://github.com/danielmiessler/SecLists.git",
    "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
}


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None, dry_run: bool = False) -> None:
    print("+", " ".join(command))
    if not dry_run:
        subprocess.run(command, cwd=cwd, env=env, check=True)


def clone_tools(dry_run: bool) -> None:
    TOOLS.mkdir(exist_ok=True)
    for name, (url, revision) in REPOSITORIES.items():
        destination = TOOLS / name
        if destination.exists():
            print(f"= {name}: already present")
            continue
        binary = SOURCE_BINARIES.get(name)
        if binary and binary_available(binary):
            print(f"= {name}: source not needed; {binary} is already available")
            continue
        run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(destination)], dry_run=dry_run)
        run(["git", "checkout", revision], cwd=destination, dry_run=dry_run)


def install_wordlists(dry_run: bool) -> None:
    """Install curated wordlist collections shallowly; never update user copies implicitly."""
    WORDLISTS.mkdir(parents=True,exist_ok=True)
    for name,url in WORDLIST_REPOSITORIES.items():
        destination=WORDLISTS/name
        if destination.exists():print(f"= {name} wordlists: already present");continue
        run(["git","clone","--depth","1","--filter=blob:none",url,str(destination)],dry_run=dry_run)


def python_executable(environment: Path) -> Path:
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def source_revision(source: Path) -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, text=True, capture_output=True, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def fingerprint(*paths: Path, salt: str = "") -> str:
    digest = hashlib.sha256(f"python={sys.version_info[:2]};{salt}".encode())
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes() if path.is_file() else b"missing")
    return digest.hexdigest()


def normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_packages(python: Path) -> dict[str, str]:
    if not python.is_file():
        return {}
    code = "import importlib.metadata,json,re;print(json.dumps({re.sub(r'[-_.]+','-',d.metadata['Name']).lower():d.version for d in importlib.metadata.distributions() if d.metadata['Name']}))"
    try:
        result = subprocess.run([str(python), "-c", code], text=True, capture_output=True, check=True)
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}


def required_packages(path: Path) -> dict[str, str | None]:
    required: dict[str, str | None] = {}
    if not path.is_file():
        return required
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http:" , "https:")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==\s*([^\s;]+))?", line)
        if match:
            required[normalize_package(match.group(1))] = match.group(2)
    return required


def environment_ready(environment: Path, wanted: str, requirements: Path | None = None, distribution: str | None = None, *, record: bool = True) -> bool:
    python = python_executable(environment)
    if not python.is_file():
        return False
    stamp = environment / STAMP_NAME
    try:
        if json.loads(stamp.read_text()).get("fingerprint") == wanted:
            return True
    except (OSError, json.JSONDecodeError):
        pass
    installed = installed_packages(python)
    required = required_packages(requirements) if requirements else {}
    if distribution:
        required[normalize_package(distribution)] = None
    if not required or any(name not in installed or (version and installed[name] != version) for name, version in required.items()):
        return False
    if record:
        stamp.write_text(json.dumps({"fingerprint": wanted}, indent=2) + "\n")
    return True


def mark_environment(environment: Path, wanted: str, dry_run: bool) -> None:
    if not dry_run:
        (environment / STAMP_NAME).write_text(json.dumps({"fingerprint": wanted}, indent=2) + "\n")


def install_python(dry_run: bool, force: bool) -> None:
    created = not python_executable(VENV).is_file()
    if created and not dry_run:
        print(f"+ create virtual environment {VENV}")
        venv.EnvBuilder(with_pip=True).create(VENV)
    python = python_executable(VENV)
    main_requirements = ROOT / "requirements.txt"
    wanted = fingerprint(main_requirements)
    if not force and not created and environment_ready(VENV, wanted, main_requirements, record=not dry_run):
        print("= application Python dependencies: already satisfied")
    else:
        if created or force:
            run([str(python), "-m", "pip", "install", "--upgrade", "pip", "wheel"], dry_run=dry_run)
        run([str(python), "-m", "pip", "install", "-r", str(main_requirements)], dry_run=dry_run)
        mark_environment(VENV, wanted, dry_run)
    integrations = (("recon-ng", "REQUIREMENTS"), ("XSStrike", "requirements.txt"), ("spiderfoot", "requirements.txt"))
    for name, requirements in integrations:
        source, environment = TOOLS / name, TOOLS / name / ".venv"
        requirement_file = source / requirements
        if not source.exists() and not dry_run:
            continue
        wanted = fingerprint(requirement_file, salt=source_revision(source))
        if not force and environment_ready(environment, wanted, requirement_file, record=not dry_run):
            print(f"= {name} Python dependencies: already satisfied")
            continue
        if not environment.exists() and not dry_run:
            print(f"+ create isolated environment {environment}")
            venv.EnvBuilder(with_pip=True).create(environment)
        run([str(python_executable(environment)), "-m", "pip", "install", "-r", str(requirement_file)], cwd=source, dry_run=dry_run)
        mark_environment(environment, wanted, dry_run)
    for name, install_target in (("theHarvester", "."),):
        source, environment = TOOLS / name, TOOLS / name / ".venv"
        if not source.exists() and not dry_run:
            continue
        if name == "theHarvester" and sys.version_info < (3, 12):
            print("! theHarvester requires Python 3.12+; skipping this optional integration")
            continue
        wanted = fingerprint(source / "pyproject.toml", salt=source_revision(source))
        if not force and environment_ready(environment, wanted, distribution="theHarvester", record=not dry_run):
            print("= theHarvester Python dependencies: already satisfied")
            continue
        if not environment.exists() and not dry_run:
            print(f"+ create isolated environment {environment}")
            venv.EnvBuilder(with_pip=True).create(environment)
        run([str(python_executable(environment)), "-m", "pip", "install", install_target], cwd=source, dry_run=dry_run)
        mark_environment(environment, wanted, dry_run)


def binary_available(name: str) -> bool:
    local = BIN / name
    return (local.is_file() and os.access(local, os.X_OK)) or shutil.which(name) is not None


def install_go(dry_run: bool, force: bool) -> None:
    if not shutil.which("go"):
        print("! Go is unavailable; skipping Go-based tools")
        return
    BIN.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GOBIN"] = str(BIN)
    for name, module in GO_TOOLS.items():
        if not force and binary_available(name):
            print(f"= {name}: already available")
        else:
            run(["go", "install", module], env=env, dry_run=dry_run)
    for name, source in (("gitleaks", "gitleaks"), ("trufflehog", "trufflehog"), ("mantra", "mantra"), ("subover", "SubOver")):
        if not force and binary_available(name):
            print(f"= {name}: already available")
        elif (TOOLS / source).exists() or dry_run:
            run(["go", "build", "-o", str(BIN / name), "."], cwd=TOOLS / source, dry_run=dry_run)


def write_env() -> None:
    destination = ROOT / ".env"
    if destination.exists():
        print("= .env: preserved")
    else:
        shutil.copy2(ROOT / ".env.example", destination)
        print("+ created .env from .env.example; change its secrets before starting the web app")


def status() -> int:
    search = os.environ.get("PATH", "").split(os.pathsep) + [str(BIN)]
    missing = [name for name in OS_COMMANDS if not any((Path(folder) / name).exists() for folder in search)]
    print(f"Python: {sys.version.split()[0]}")
    print(f"Tool repositories: {sum((TOOLS / name).exists() for name in REPOSITORIES)}/{len(REPOSITORIES)}")
    managed = set(GO_TOOLS) | {"gitleaks", "trufflehog", "mantra", "subover"}
    print(f"Available managed binaries: {sum(binary_available(name) for name in managed)}/{len(managed)}")
    if missing:
        print("Missing OS commands (install with your system package manager): " + ", ".join(missing))
    print("Results and runtime state: preserved")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Recon Pipeline and its managed integrations")
    parser.add_argument("command", nargs="?", choices=("install", "status"), default="install")
    parser.add_argument("--dry-run", action="store_true", help="show planned commands without changing files")
    parser.add_argument("--force", action="store_true", help="reinstall dependencies and rebuild binaries")
    args = parser.parse_args()
    if args.command == "status":
        return status()
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required")
    if not shutil.which("git"):
        parser.error("git is required")
    clone_tools(args.dry_run)
    install_wordlists(args.dry_run)
    install_python(args.dry_run, args.force)
    install_go(args.dry_run, args.force)
    if not args.dry_run:
        write_env()
    print("\nInstallation complete. Existing results were not modified.")
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
