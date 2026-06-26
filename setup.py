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
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
BIN = TOOLS / "bin"
VENV = ROOT / "venv"
WORDLISTS = TOOLS / "wordlists"
WAPITI_ENV = TOOLS / "wapiti" / ".venv"
NIKTO_PERL = TOOLS / "nikto" / "perl5"
LOCAL_BIN_DIRS = (ROOT / "bin", BIN)

# Revisions tested with Recon Pipeline 2.0. Updating is an explicit operation.
REPOSITORIES = {
    "SubOver": ("https://github.com/Ice3man543/SubOver.git", "3d258e254ab5b5f37ec6fc2dcd55b45f266ac5f6"),
    "XSStrike": ("https://github.com/s0md3v/XSStrike.git", "ab27955d367432f944d8f29897e09c15356e76f7"),
    "dnsenum": ("https://github.com/fwaeytens/dnsenum.git", "e3336c51a6d43d1ebb292970958e9cdc0cf93419"),
    "gitleaks": ("https://github.com/gitleaks/gitleaks.git", "8ad8470035d31a209322c580153b45c18e21b980"),
    "mantra": ("https://github.com/Brosck/mantra.git", "6026816210df756f8cc8e9d637b9f49fb277a5f0"),
    "nikto": ("https://github.com/sullo/nikto.git", "999670cb6a939b6c93840ce666941756e4c5dcf5"),
    "recon-ng": ("https://github.com/lanmaster53/recon-ng.git", "c08acee0f84645ecf521ec616ac2dde94cbc1d63"),
    "recon-ng-marketplace": ("https://github.com/lanmaster53/recon-ng-marketplace.git", "9527714d2bb38886422bab5f1c4724d4a20d3057"),
    "spiderfoot": ("https://github.com/smicallef/spiderfoot.git", "0f815a203afebf05c98b605dba5cf0475a0ee5fd"),
    "sqlmap": ("https://github.com/sqlmapproject/sqlmap.git", "e1aac02ef2ca017e2dc5f4be8883db59d039295a"),
    "testssl.sh": ("https://github.com/testssl/testssl.sh.git", "b5a83f5f1087389ca2fd7b2872b8cbf438d05f91"),
    "theHarvester": ("https://github.com/laramies/theHarvester.git", "14d9f2999657f3285de78e5c42c66b626e84c2a1"),
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

OS_COMMANDS = ("git", "nmap", "whatweb", "whois", "dig", "sslscan", "perl")
STAMP_NAME = ".recon-pipeline-install.json"
SOURCE_BINARIES = {"SubOver": "subover", "gitleaks": "gitleaks", "mantra": "mantra"}
TRUFFLEHOG_INSTALL_URL = "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
SOURCE_GO_BINARIES = {"gitleaks", "mantra", "subover"}
LEGACY_GO_MODULES = {
    "SubOver": (
        "local/subover",
        ("github.com/parnurzeal/gorequest v0.3.0",),
    ),
}
WORDLIST_REPOSITORIES = {
    "SecLists": "https://github.com/danielmiessler/SecLists.git",
    "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
}
PYTHON_INTEGRATIONS = (
    ("recon-ng", "REQUIREMENTS"),
    ("XSStrike", "requirements.txt"),
    ("spiderfoot", "requirements.txt"),
)
PYPI_TOOL_INTEGRATIONS = (
    ("wapiti", WAPITI_ENV, "wapiti3", "wapiti3"),
)
PERL_TOOL_INTEGRATIONS = (
    ("nikto", TOOLS / "nikto", NIKTO_PERL, ("XML::Writer",)),
)


@dataclass(frozen=True)
class RequirementSpec:
    name: str
    specifier: str = ""


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None, dry_run: bool = False) -> None:
    print("+", " ".join(command))
    if not dry_run:
        subprocess.run(command, cwd=cwd, env=env, check=True)


def pip_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    env.setdefault("PIP_CACHE_DIR", str(ROOT / ".pip-cache"))
    return env


def clone_tools(dry_run: bool) -> None:
    TOOLS.mkdir(exist_ok=True)
    for name, (url, revision) in REPOSITORIES.items():
        destination = TOOLS / name
        if destination.exists():
            print(f"= {name}: already present")
            continue
        binary = SOURCE_BINARIES.get(name)
        if binary and skip_available_binary(binary):
            print(f"= {name}: source checkout not needed")
            continue
        run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(destination)], dry_run=dry_run)
        run(["git", "checkout", revision], cwd=destination, dry_run=dry_run)


def install_wordlists(dry_run: bool) -> None:
    """Install curated wordlist collections shallowly; never update user copies implicitly."""
    WORDLISTS.mkdir(parents=True, exist_ok=True)
    for name, url in WORDLIST_REPOSITORIES.items():
        destination = WORDLISTS / name
        if destination.exists():
            print(f"= {name} wordlists: already present")
            continue
        run(["git", "clone", "--depth", "1", "--filter=blob:none", url, str(destination)], dry_run=dry_run)


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


def requirement_parser():
    for module in ("packaging.requirements", "pip._vendor.packaging.requirements"):
        try:
            imported = __import__(module, fromlist=["Requirement"])
            return imported.Requirement
        except (ImportError, AttributeError):
            continue
    return None


def specifier_parser():
    for module in ("packaging.specifiers", "pip._vendor.packaging.specifiers"):
        try:
            imported = __import__(module, fromlist=["SpecifierSet"])
            return imported.SpecifierSet
        except (ImportError, AttributeError):
            continue
    return None


def installed_packages(python: Path) -> dict[str, str]:
    if not python.is_file():
        return {}
    code = "import importlib.metadata,json,re;print(json.dumps({re.sub(r'[-_.]+','-',d.metadata['Name']).lower():d.version for d in importlib.metadata.distributions() if d.metadata['Name']}))"
    try:
        result = subprocess.run([str(python), "-c", code], text=True, capture_output=True, check=True)
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}


def required_packages(path: Path) -> dict[str, RequirementSpec]:
    required: dict[str, RequirementSpec] = {}
    if not path.is_file():
        return required
    parser = requirement_parser()
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http:" , "https:")):
            continue
        if parser:
            try:
                requirement = parser(line)
            except Exception:
                continue
            if requirement.marker and not requirement.marker.evaluate():
                continue
            name = normalize_package(requirement.name)
            required[name] = RequirementSpec(name=name, specifier=str(requirement.specifier))
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", line)
        if match:
            name = normalize_package(match.group(1))
            required[name] = RequirementSpec(name=name, specifier=(match.group(2) or "").strip())
    return required


def requirement_satisfied(installed: dict[str, str], requirement: RequirementSpec) -> bool:
    version = installed.get(requirement.name)
    if not version:
        return False
    if not requirement.specifier:
        return True
    parser = specifier_parser()
    if parser:
        try:
            return parser(requirement.specifier).contains(version, prereleases=True)
        except Exception:
            return False
    exact = re.fullmatch(r"==\s*([^,;\s]+)", requirement.specifier)
    return bool(exact and version == exact.group(1))


def missing_requirements(python: Path, requirements: Path | None = None, distribution: str | None = None) -> list[str]:
    installed = installed_packages(python)
    required = required_packages(requirements) if requirements else {}
    if distribution:
        name = normalize_package(distribution)
        required[name] = RequirementSpec(name=name)
    missing: list[str] = []
    for name, requirement in sorted(required.items()):
        if requirement_satisfied(installed, requirement):
            continue
        current = installed.get(name)
        want = requirement.specifier or "required"
        missing.append(f"{name} ({current or 'missing'} -> {want})")
    return missing


def perl_environment(perl_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    lib = perl_root / "lib" / "perl5"
    home = perl_root / "home"
    cpan_home = perl_root / "cpan"
    env["HOME"] = str(home)
    env["PERL5LIB"] = str(lib) + (os.pathsep + env["PERL5LIB"] if env.get("PERL5LIB") else "")
    env["PERL_MM_OPT"] = f"INSTALL_BASE={perl_root}"
    env["PERL_MB_OPT"] = f"--install_base {perl_root}"
    env["PERL_CPAN_HOME"] = str(cpan_home)
    env["PERL_MM_USE_DEFAULT"] = "1"
    env["NONINTERACTIVE_TESTING"] = "1"
    env.setdefault("PERL_CPANM_OPT", "--notest")
    return env


def missing_perl_modules(perl_root: Path, modules: tuple[str, ...]) -> list[str]:
    env = perl_environment(perl_root)
    missing = []
    for module in modules:
        result = subprocess.run(["perl", "-M" + module, "-e", "1"], env=env, text=True, capture_output=True)
        if result.returncode != 0:
            missing.append(module)
    return missing


def install_perl_tools(dry_run: bool, force: bool) -> None:
    if not shutil.which("perl"):
        print("! perl is unavailable; skipping Perl tool dependencies")
        return
    for name, source, perl_root, modules in PERL_TOOL_INTEGRATIONS:
        if not source.exists() and not dry_run:
            continue
        missing = list(modules) if force else missing_perl_modules(perl_root, modules)
        if not missing:
            print(f"= {name} Perl dependencies: already satisfied")
            continue
        if not shutil.which("cpan"):
            print(f"! cpan is unavailable; skipping {name} Perl dependencies")
            continue
        perl_root.mkdir(parents=True, exist_ok=True)
        (perl_root / "home").mkdir(parents=True, exist_ok=True)
        (perl_root / "cpan").mkdir(parents=True, exist_ok=True)
        env = perl_environment(perl_root)
        for module in missing:
            run(["cpan", "-T", "-i", module], cwd=source if source.exists() else ROOT, env=env, dry_run=dry_run)


def integration_skip_reason(name: str) -> str | None:
    if name == "spiderfoot" and sys.version_info >= (3, 14):
        return "SpiderFoot pins lxml<5, which does not build on Python 3.14+; skipping this optional integration"
    return None


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
    if missing_requirements(python, requirements, distribution):
        return False
    if record:
        stamp.write_text(json.dumps({"fingerprint": wanted}, indent=2) + "\n")
    return True


def mark_environment(environment: Path, wanted: str, dry_run: bool) -> None:
    if not dry_run:
        (environment / STAMP_NAME).write_text(json.dumps({"fingerprint": wanted}, indent=2) + "\n")


def ensure_virtualenv(environment: Path, dry_run: bool) -> bool:
    python = python_executable(environment)
    if python.is_file():
        return False
    if dry_run:
        print(f"+ create virtual environment {environment}")
    else:
        print(f"+ create virtual environment {environment}")
        venv.EnvBuilder(with_pip=True).create(environment)
    return True


def ensure_pip(environment: Path, dry_run: bool) -> None:
    python = python_executable(environment)
    if dry_run:
        if not python.is_file():
            print(f"+ {python} -m ensurepip --upgrade")
        return
    try:
        subprocess.run([str(python), "-m", "pip", "--version"], text=True, capture_output=True, check=True)
        return
    except (OSError, subprocess.SubprocessError):
        pass
    run([str(python), "-m", "ensurepip", "--upgrade"])
    subprocess.run([str(python), "-m", "pip", "--version"], text=True, capture_output=True, check=True)


def install_python(dry_run: bool, force: bool) -> None:
    created = ensure_virtualenv(VENV, dry_run)
    ensure_pip(VENV, dry_run)
    python = python_executable(VENV)
    main_requirements = ROOT / "requirements.txt"
    pip_env = pip_environment()
    wanted = fingerprint(main_requirements)
    if not force and not created and environment_ready(VENV, wanted, main_requirements, record=not dry_run):
        print("= application Python dependencies: already satisfied")
    else:
        if created or force:
            run([str(python), "-m", "pip", "install", "--upgrade", "pip", "wheel"], env=pip_env, dry_run=dry_run)
        run([str(python), "-m", "pip", "install", "-r", str(main_requirements)], env=pip_env, dry_run=dry_run)
        mark_environment(VENV, wanted, dry_run)
    for name, requirements in PYTHON_INTEGRATIONS:
        source, environment = TOOLS / name, TOOLS / name / ".venv"
        requirement_file = source / requirements
        if not source.exists() and not dry_run:
            continue
        if reason := integration_skip_reason(name):
            print(f"! {reason}")
            continue
        wanted = fingerprint(requirement_file, salt=source_revision(source))
        if not force and environment_ready(environment, wanted, requirement_file, record=not dry_run):
            print(f"= {name} Python dependencies: already satisfied")
            continue
        ensure_virtualenv(environment, dry_run)
        ensure_pip(environment, dry_run)
        run([str(python_executable(environment)), "-m", "pip", "install", "-r", str(requirement_file)], cwd=source, env=pip_env, dry_run=dry_run)
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
        ensure_virtualenv(environment, dry_run)
        ensure_pip(environment, dry_run)
        run([str(python_executable(environment)), "-m", "pip", "install", install_target], cwd=source, env=pip_env, dry_run=dry_run)
        mark_environment(environment, wanted, dry_run)
    for name, environment, package, distribution in PYPI_TOOL_INTEGRATIONS:
        wanted = fingerprint(ROOT / "setup.py", salt=f"{name}:{package}")
        if not force and environment_ready(environment, wanted, distribution=distribution, record=not dry_run):
            print(f"= {name} Python tool: already satisfied")
            continue
        ensure_virtualenv(environment, dry_run)
        ensure_pip(environment, dry_run)
        run([str(python_executable(environment)), "-m", "pip", "install", package], env=pip_env, dry_run=dry_run)
        mark_environment(environment, wanted, dry_run)


def local_binary(name: str) -> Path | None:
    for folder in LOCAL_BIN_DIRS:
        local = folder / name
        if local.is_file() and os.access(local, os.X_OK):
            return local
    return None


def system_binary(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def binary_location(name: str) -> Path | None:
    return local_binary(name) or system_binary(name)


def binary_available(name: str) -> bool:
    return binary_location(name) is not None


def skip_available_binary(name: str, *, force: bool = False) -> bool:
    if force:
        return False
    location = binary_location(name)
    if not location:
        return False
    print(f"= {name}: already available at {location}")
    return True


def ensure_legacy_go_module(source: Path, module: str, requirements: tuple[str, ...], dry_run: bool) -> None:
    go_mod = source / "go.mod"
    if go_mod.is_file():
        return
    lines = [f"module {module}", "", "go 1.20"]
    if requirements:
        lines.extend(["", "require (", *(f"\t{requirement}" for requirement in requirements), ")"])
    content = "\n".join(lines) + "\n"
    if dry_run:
        print(f"+ create {go_mod} for legacy Go build")
    else:
        go_mod.write_text(content)


def install_source_go_binary(name: str, source_name: str, dry_run: bool) -> None:
    source = TOOLS / source_name
    if not source.exists() and not dry_run:
        print(f"! {name}: source checkout missing; skipping")
        return
    if source_name in LEGACY_GO_MODULES:
        module, requirements = LEGACY_GO_MODULES[source_name]
        ensure_legacy_go_module(source, module, requirements, dry_run)
    BIN.mkdir(parents=True, exist_ok=True)
    try:
        run(["go", "build", "-mod=mod", "-o", str(BIN / name), "."], cwd=source, dry_run=dry_run)
    except subprocess.CalledProcessError as exc:
        print(f"! {name}: build failed with exit code {exc.returncode}; skipping")


def install_go(dry_run: bool, force: bool) -> None:
    go_available = shutil.which("go") is not None
    env = os.environ.copy()
    env["GOBIN"] = str(BIN)
    for name, module in GO_TOOLS.items():
        if skip_available_binary(name, force=force):
            continue
        if not go_available:
            print(f"! Go is unavailable; skipping {name}")
            continue
        BIN.mkdir(parents=True, exist_ok=True)
        run(["go", "install", module], env=env, dry_run=dry_run)
    for name, source in (("gitleaks", "gitleaks"), ("mantra", "mantra"), ("subover", "SubOver")):
        if skip_available_binary(name, force=force):
            continue
        if not go_available:
            print(f"! Go is unavailable; skipping {name}")
            continue
        install_source_go_binary(name, source, dry_run)


def install_trufflehog(dry_run: bool, force: bool) -> None:
    if skip_available_binary("trufflehog", force=force):
        return
    if not shutil.which("curl"):
        print("! curl is unavailable; skipping trufflehog installer")
        return
    BIN.mkdir(parents=True, exist_ok=True)
    command = f"curl -sSfL {TRUFFLEHOG_INSTALL_URL} | sh -s -- -b {BIN}"
    print("+", command)
    if dry_run:
        return
    script = subprocess.run(["curl", "-sSfL", TRUFFLEHOG_INSTALL_URL], text=True, capture_output=True, check=True).stdout
    subprocess.run(["sh", "-s", "--", "-b", str(BIN)], input=script, text=True, check=True)


def write_env() -> None:
    destination = ROOT / ".env"
    example = ROOT / ".env.example"
    if destination.exists():
        print("= .env: preserved")
    elif example.exists():
        shutil.copy2(example, destination)
        print("+ created .env from .env.example; change its secrets before starting the web app")
    else:
        print("! .env not created; provide .env or .env.example before starting the web app")


def validate_project_files(parser: argparse.ArgumentParser) -> None:
    required = [ROOT / "requirements.txt"]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if not (ROOT / ".env").is_file() and not (ROOT / ".env.example").is_file():
        missing.append(".env or .env.example")
    if missing:
        parser.error("missing required project file(s): " + ", ".join(missing))


def executable_in_search_path(name: str, search: list[str]) -> bool:
    for folder in search:
        executable = Path(folder) / name
        if executable.is_file() and os.access(executable, os.X_OK):
            return True
    return False


def print_missing(label: str, missing: list[str]) -> None:
    if missing:
        print(f"{label}: " + ", ".join(missing))


def status() -> int:
    search = [str(path) for path in LOCAL_BIN_DIRS] + os.environ.get("PATH", "").split(os.pathsep)
    missing = [name for name in OS_COMMANDS if not executable_in_search_path(name, search)]
    go_managed = set(GO_TOOLS) | SOURCE_GO_BINARIES
    managed = go_managed | {"trufflehog"}
    missing_go_managed = sorted(name for name in go_managed if not binary_available(name))
    missing_installer_managed = ["trufflehog"] if not binary_available("trufflehog") else []
    missing_repositories = sorted(name for name in REPOSITORIES if not (TOOLS / name).exists())
    missing_wordlists = sorted(name for name in WORDLIST_REPOSITORIES if not (WORDLISTS / name).exists())
    app_missing = missing_requirements(python_executable(VENV), ROOT / "requirements.txt")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Tool repositories: {sum((TOOLS / name).exists() for name in REPOSITORIES)}/{len(REPOSITORIES)}")
    print(f"Available managed binaries: {sum(binary_available(name) for name in managed)}/{len(managed)}")
    print(f"Wordlist repositories: {sum((WORDLISTS / name).exists() for name in WORDLIST_REPOSITORIES)}/{len(WORDLIST_REPOSITORIES)}")
    if python_executable(VENV).is_file() and not app_missing:
        print("Application Python dependencies: satisfied")
    elif app_missing:
        print_missing("Application Python dependencies to repair", app_missing)
    else:
        print("Application Python dependencies: virtual environment missing")
    for name, requirements in PYTHON_INTEGRATIONS:
        source, environment = TOOLS / name, TOOLS / name / ".venv"
        if not source.exists():
            continue
        if reason := integration_skip_reason(name):
            print(f"{name} Python dependencies: skipped ({reason})")
            continue
        integration_missing = missing_requirements(python_executable(environment), source / requirements)
        if integration_missing:
            print_missing(f"{name} Python dependencies to repair", integration_missing)
    harvester = TOOLS / "theHarvester"
    if harvester.exists() and sys.version_info >= (3, 12):
        harvester_missing = missing_requirements(python_executable(harvester / ".venv"), distribution="theHarvester")
        if harvester_missing:
            print_missing("theHarvester Python dependencies to repair", harvester_missing)
    for name, environment, _package, distribution in PYPI_TOOL_INTEGRATIONS:
        tool_missing = missing_requirements(python_executable(environment), distribution=distribution)
        if python_executable(environment).is_file() and not tool_missing:
            print(f"{name} Python tool: satisfied")
        elif tool_missing:
            print_missing(f"{name} Python tool to repair", tool_missing)
        else:
            print(f"{name} Python tool: virtual environment missing")
    for name, source, perl_root, modules in PERL_TOOL_INTEGRATIONS:
        if source.exists():
            perl_missing = missing_perl_modules(perl_root, modules)
            if perl_missing:
                print_missing(f"{name} Perl dependencies to repair", perl_missing)
            else:
                print(f"{name} Perl dependencies: satisfied")
    print_missing("Missing OS commands (install with your system package manager)", missing)
    print_missing("Missing Go-managed binaries (rerun setup.py after Go is installed)", missing_go_managed)
    print_missing("Missing installer-managed binaries (rerun setup.py after curl is installed)", missing_installer_managed)
    print_missing("Missing tool repositories (rerun setup.py)", missing_repositories)
    print_missing("Missing wordlist repositories (rerun setup.py)", missing_wordlists)
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
    validate_project_files(parser)
    clone_tools(args.dry_run)
    install_wordlists(args.dry_run)
    install_python(args.dry_run, args.force)
    install_perl_tools(args.dry_run, args.force)
    install_go(args.dry_run, args.force)
    install_trufflehog(args.dry_run, args.force)
    if not args.dry_run:
        write_env()
    print("\nInstallation complete. Existing results were not modified.")
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
