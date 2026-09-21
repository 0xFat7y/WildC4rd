#!/usr/bin/env python3
"""
Wildcard Recon v2

Authorized security testing and asset inventory only.
This tool is intentionally limited to discovery, metadata collection,
HTTP reachability checks, crawling, and local analysis of downloaded JS.
It does not exploit findings or run vulnerability templates.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import requests
from requests import Session


# ---------------------------------------------------------------------------
# Constants and configuration
# ---------------------------------------------------------------------------

STAGE_ORDER = (
    "dorks",
    "whois",
    "subdomains",
    "httpx",
    "historical",
    "params",
    "gf",
    "katana",
    "js_analysis",
    "eyewitness",
    "summary",
)

TOOL_ALIASES: dict[str, list[str]] = {
    "subfinder": ["subfinder"],
    "amass": ["amass"],
    "assetfinder": ["assetfinder"],
    "httpx": ["httpx", "httpx-toolkit"],
    "waybackurls": ["waybackurls"],
    "gau": ["gau"],
    "gf": ["gf"],
    "katana": ["katana"],
    "xnLinkFinder": ["xnLinkFinder", "xnlinkfinder", "xnLinkFinder.py"],
    "whois": ["whois"],
}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    ("AWS Secret Key", re.compile(r"(?i)aws.{0,30}secret.{0,30}['\"]([\w/+]{40})['\"]")),
    ("Google API Key", re.compile(r"(AIza[0-9A-Za-z\-_]{35})")),
    ("Firebase Key", re.compile(r"(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,})")),
    ("GitHub Token", re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("JWT Token", re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("Bearer Token", re.compile(r"(?i)bearer\s+([A-Za-z0-9\-_\.~+/]{20,})")),
    ("Slack Token", re.compile(r"(xox[baprs]-[0-9A-Za-z-]{10,80})")),
    ("Stripe Live Key", re.compile(r"(sk_live_[0-9A-Za-z]{16,})")),
    ("Twilio Account SID", re.compile(r"(AC[a-z0-9]{32})")),
    ("SendGrid API Key", re.compile(r"(SG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{20,})")),
    ("Shopify Token", re.compile(r"(shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32})")),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
]

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
ENDPOINT_RE = re.compile(r"[\"'](\/[^\"'<>\\\s]{1,400})[\"']")

def print_banner() -> None:
    esc = chr(27)
    red = esc + "[91m"
    white = esc + "[97m"
    gray = esc + "[90m"
    bold = esc + "[1m"
    reset = esc + "[0m"
    print()
    print(f"  {bold}{white}██╗    ██╗{red}██╗{white}██╗     ██████╗{red} ██████╗{white} ██╗  ██╗██████╗ ██████╗{reset}")
    print(f"  {bold}{white}██║    ██║{red}██║{white}██║     ██╔══██╗{red}██╔════╝{white}██║  ██║██╔══██╗██╔══██╗{reset}")
    print(f"  {bold}{white}██║ █╗ ██║{red}██║{white}██║     ██║  ██║{red}██║     {white}███████║██████╔╝██║  ██║{reset}")
    print(f"  {bold}{white}██║███╗██║{red}██║{white}██║     ██║  ██║{red}██║     {white}╚════██║██╔══██╗██║  ██║{reset}")
    print(f"  {bold}{white}╚███╔███╔╝{red}██║{white}███████╗██████╔╝{red}╚██████╗{white}     ██║██║  ██║██████╔╝{reset}")
    print(f"  {bold}{gray} ╚══╝╚══╝ {red}╚═╝{gray}╚══════╝╚═════╝  {red}╚═════╝{gray}     ╚═╝╚═╝  ╚═╝╚═════╝ {reset}")
    print()


@dataclass
class Config:
    target: str
    output_root: Path
    profile: str = "standard"
    selected_stages: tuple[str, ...] = STAGE_ORDER
    open_browser: bool = False
    dry_run: bool = False
    resume_manifest: Optional[Path] = None
    insecure_tls: bool = False
    probe_history: bool = False
    subfinder_threads: int = 30
    httpx_threads: int = 35
    katana_concurrency: int = 15
    js_workers: int = 5
    max_js_bytes: int = 10 * 1024 * 1024
    max_targets: int = 50
    gau_timeout: int = 900
    command_timeout: int = 1800


@dataclass(frozen=True)
class Scope:
    roots: tuple[str, ...]

    def contains(self, hostname: str) -> bool:
        host = normalize_hostname(hostname)
        if not host:
            return False
        return any(host == root or host.endswith("." + root) for root in self.roots)


@dataclass
class CommandResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False


class ReconLogger:
    def __init__(self, log_path: Path, quiet: bool = False):
        self.quiet = quiet
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        name = f"wildcard.{os.getpid()}.{uuid.uuid4().hex}"
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        handler = logging.FileHandler(self.log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self._logger.addHandler(handler)

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)

    def _write(self, level: str, message: str) -> None:
        getattr(self._logger, level.lower(), self._logger.info)(message)
        if not self.quiet:
            print(f"[{level:<5}] {message}")

    def info(self, message: str) -> None:
        self._write("INFO", message)

    def ok(self, message: str) -> None:
        self._write("OK", message)

    def warn(self, message: str) -> None:
        self._write("WARN", message)

    def error(self, message: str) -> None:
        self._write("ERROR", message)

    def debug(self, message: str) -> None:
        self._write("DEBUG", message)


@dataclass
class Context:
    config: Config
    scope: Scope
    run_dir: Path
    manifest_path: Path
    logger: ReconLogger
    tools: dict[str, Optional[str]]
    session: Session
    manifest: dict[str, Any]


# ---------------------------------------------------------------------------
# General utilities
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def write_lines(path: Path, lines: Iterable[str]) -> None:
    values = sorted({str(line).strip() for line in lines if str(line).strip()})
    atomic_write_text(path, ("\n".join(values) + "\n") if values else "")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return []


def write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if "//" in value:
        parsed = urlparse(value if value.startswith(("http://", "https://")) else "//" + value)
        value = parsed.hostname or ""
    else:
        value = value.split("/", 1)[0]
        if value.count(":") == 1:
            value = value.split(":", 1)[0]
    if not value or len(value) > 253 or ".." in value or " " in value:
        return ""
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return ""
    return value


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("target is empty")
    candidate = value if "://" in value else "//" + value
    parsed = urlparse(candidate)
    if parsed.port is not None:
        raise ValueError("ports are not accepted in domain mode")
    host = normalize_hostname(parsed.hostname or "")
    if not host:
        raise ValueError(f"invalid domain: {raw!r}")
    return host


def build_scope(target: str, scope_file: Optional[Path]) -> Scope:
    roots = {normalize_target(target)}
    if scope_file:
        if not scope_file.exists():
            raise ValueError(f"scope file not found: {scope_file}")
        for line in read_lines(scope_file):
            if line.startswith("#"):
                continue
            try:
                roots.add(normalize_target(line))
            except ValueError as exc:
                raise ValueError(f"invalid scope entry {line!r}: {exc}") from exc
    return Scope(tuple(sorted(roots)))


def normalize_url(value: str, scope: Scope) -> Optional[str]:
    raw = value.strip().strip("<>\"'`),;\n\r\t")
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        return None
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        if parsed.username or parsed.password or parsed.port is not None:
            return None
        if parsed.scheme.lower() not in {"http", "https"} or not scope.contains(host):
            return None
        clean = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower())
        return urlunparse(clean)
    except (ValueError, UnicodeError):
        return None


def normalize_subdomain(value: str, scope: Scope) -> Optional[str]:
    candidate = value.strip().lstrip("*.")
    if candidate.startswith(("http://", "https://")):
        try:
            candidate = urlparse(candidate).hostname or ""
        except ValueError:
            return None
    host = normalize_hostname(candidate)
    return host if host and scope.contains(host) else None


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "target"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    visible = 4 if len(value) < 20 else 5
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


def command_preview(cmd: list[str]) -> str:
    return " ".join(arg if re.fullmatch(r"[A-Za-z0-9_./:=+-]+", arg) else repr(arg) for arg in cmd)


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
            time.sleep(0.5)
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.terminate()
            time.sleep(0.5)
            if process.poll() is None:
                process.kill()
    except (ProcessLookupError, OSError):
        pass


def run_cmd(
    cmd: list[str],
    logger: ReconLogger,
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    input_data: Optional[str] = None,
    output_file: Optional[Path] = None,
) -> CommandResult:
    started = time.monotonic()
    logger.debug(f"exec: {command_preview(cmd)}")
    output_handle = None
    try:
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_handle = output_file.open("w", encoding="utf-8")
            stdout_target: Any = output_handle
        else:
            stdout_target = subprocess.PIPE
        process = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=(os.name == "posix"),
        )
        try:
            stdout, stderr = process.communicate(input=input_data, timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(process)
            stdout, stderr = process.communicate()
        except KeyboardInterrupt:
            terminate_process_group(process)
            process.communicate()
            raise
        returncode = process.returncode if process.returncode is not None else -1
        duration = time.monotonic() - started
        result = CommandResult(
            ok=(returncode == 0 and not timed_out),
            returncode=returncode,
            stdout=stdout or "",
            stderr=(stderr or "")[-8000:],
            duration_seconds=round(duration, 3),
            timed_out=timed_out,
        )
        if timed_out:
            logger.warn(f"command timed out after {timeout}s: {cmd[0]}")
        elif returncode != 0:
            logger.warn(f"command exited {returncode}: {cmd[0]} — {result.stderr[:300]}")
        return result
    except FileNotFoundError:
        return CommandResult(False, 127, "", f"not found: {cmd[0]}", time.monotonic() - started)
    except OSError as exc:
        return CommandResult(False, 126, "", str(exc), time.monotonic() - started)
    finally:
        if output_handle:
            output_handle.close()


def tool_command(ctx: Context, name: str, *args: str) -> Optional[list[str]]:
    path = ctx.tools.get(name)
    if not path:
        return None
    if path.endswith(".py"):
        return [sys.executable, path, *args]
    return [path, *args]


def detect_tools(logger: ReconLogger) -> dict[str, Optional[str]]:
    found: dict[str, Optional[str]] = {}
    for name, candidates in TOOL_ALIASES.items():
        path = next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None)
        found[name] = path
        logger.info(f"tool {name}: {path or 'not found (stage will skip)'}")
    return found


def session_for(config: Config) -> Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "WildcardRecon/2.0 (authorized asset inventory)",
        "Accept": "application/json, text/plain, */*",
    })
    session.verify = not config.insecure_tls
    return session


def fetch_text(ctx: Context, url: str, *, max_bytes: int, timeout: tuple[int, int] = (5, 20)) -> Optional[str]:
    clean = normalize_url(url, ctx.scope)
    if not clean:
        return None
    try:
        response = ctx.session.get(clean, timeout=timeout, allow_redirects=False, stream=True)
        if response.status_code != 200:
            response.close()
            return None
        content_length = response.headers.get("Content-Length", "")
        if content_length.isdigit() and int(content_length) > max_bytes:
            response.close()
            ctx.logger.warn(f"skipping oversized response: {clean}")
            return None
        data = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            data.extend(chunk)
            if len(data) > max_bytes:
                response.close()
                ctx.logger.warn(f"response exceeded size limit: {clean}")
                return None
        encoding = response.encoding or "utf-8"
        response.close()
        return bytes(data).decode(encoding, errors="replace")
    except requests.RequestException as exc:
        ctx.logger.debug(f"fetch failed for {clean}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Manifest and stage orchestration
# ---------------------------------------------------------------------------


def save_manifest(ctx: Context) -> None:
    write_json(ctx.manifest_path, ctx.manifest)


def stage_is_complete(ctx: Context, name: str) -> bool:
    return ctx.manifest.get("stages", {}).get(name, {}).get("status") == "success"


def run_stage(ctx: Context, name: str, function: Callable[[Context], Any]) -> Any:
    if name not in ctx.config.selected_stages:
        return None
    if stage_is_complete(ctx, name):
        ctx.logger.info(f"stage {name}: skipped (already complete; resume)")
        return None
    if ctx.config.dry_run:
        ctx.logger.info(f"stage {name}: planned (dry-run)")
        ctx.manifest.setdefault("stages", {})[name] = {"status": "dry-run", "finished_at": utc_now()}
        save_manifest(ctx)
        return None
    started = time.monotonic()
    ctx.manifest.setdefault("stages", {})[name] = {"status": "running", "started_at": utc_now()}
    save_manifest(ctx)
    ctx.logger.info(f"stage {name}: started")
    try:
        result = function(ctx)
        ctx.manifest["stages"][name] = {
            "status": "success",
            "started_at": ctx.manifest["stages"][name].get("started_at"),
            "finished_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        save_manifest(ctx)
        ctx.logger.ok(f"stage {name}: complete")
        return result
    except Exception as exc:  # stages are isolated so one optional tool cannot destroy the run
        ctx.manifest["stages"][name] = {
            "status": "failed",
            "finished_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "error": repr(exc),
        }
        save_manifest(ctx)
        ctx.logger.error(f"stage {name}: failed safely — {exc}")
        return None


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def stage_dorks(ctx: Context) -> None:
    target = ctx.config.target
    dorks = [
        ("Subdomains 1st level", f"site:*.{target}"),
        ("Subdomains 2nd level", f"site:*.*.{target}"),
        ("Subdomains 3rd level", f"site:*.*.*.{target}"),
        ("Root domain", f"site:{target}"),
        ("Root domain excluding www", f"site:{target} -www"),
        ("URL mentions", f"inurl:{target}"),
        ("Open directories", f'intitle:"Index of" site:*.{target}'),
        ("PDF references", f'"{target}" filetype:pdf'),
        ("Configuration references", f'"{target}" (ext:env OR ext:log OR ext:conf)'),
    ]
    raw = [query for _, query in dorks]
    google = [f"# {label}\nhttps://www.google.com/search?{urlencode({'q': query, 'num': '100'})}" for label, query in dorks]
    write_lines(ctx.run_dir / "dorks.txt", raw)
    atomic_write_text(ctx.run_dir / "google_dorks.txt", "\n\n".join(google) + "\n")
    ctx.logger.info("dorks saved separately; they are never sent to HTTP probing")
    if ctx.config.open_browser:
        for _, query in dorks:
            webbrowser.open_new_tab(f"https://www.google.com/search?{urlencode({'q': query, 'num': '100'})}")


def stage_whois(ctx: Context) -> None:
    command = tool_command(ctx, "whois", ctx.config.target)
    if not command:
        ctx.logger.warn("whois unavailable; skipping")
        return
    output = ctx.run_dir / "whois.txt"
    result = run_cmd(command, ctx.logger, timeout=60, output_file=output)
    if not result.ok:
        ctx.logger.warn(f"whois failed: {result.stderr[:300]}")


def collect_host_values(lines: Iterable[str], scope: Scope) -> set[str]:
    values: set[str] = set()
    for line in lines:
        for token in re.split(r"[\s,]+", line):
            host = normalize_subdomain(token, scope)
            if host:
                values.add(host)
    return values


def crtsh_subdomains(ctx: Context) -> set[str]:
    endpoint = f"https://crt.sh/?q={quote('%.' + ctx.config.target)}&output=json"
    for attempt in range(3):
        try:
            response = ctx.session.get(endpoint, timeout=(10, 45), allow_redirects=False)
            if response.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            if response.status_code != 200:
                time.sleep(2 ** attempt)
                continue
            entries = response.json()
            values: set[str] = set()
            for entry in entries if isinstance(entries, list) else []:
                for raw in str(entry.get("name_value", "")).splitlines():
                    host = normalize_subdomain(raw, ctx.scope)
                    if host:
                        values.add(host)
            return values
        except (requests.RequestException, ValueError, TypeError) as exc:
            ctx.logger.debug(f"crt.sh attempt {attempt + 1} failed: {exc}")
            time.sleep(2 ** attempt)
    ctx.logger.warn("crt.sh unavailable after bounded retries")
    return set()


def stage_subdomains(ctx: Context) -> None:
    discovered: set[str] = {ctx.config.target}
    sources: dict[str, int] = {}

    for name in ("subfinder", "amass", "assetfinder"):
        if name == "subfinder":
            output = ctx.run_dir / "subfinder.txt"
            command = tool_command(ctx, name, "-d", ctx.config.target, "-silent", "-all", "-t", str(ctx.config.subfinder_threads), "-timeout", "30", "-o", str(output))
            result = run_cmd(command, ctx.logger, timeout=ctx.config.command_timeout, output_file=None) if command else None
            values = collect_host_values(read_lines(output), ctx.scope) if output.exists() else set()
            if result and result.stdout:
                values |= collect_host_values(result.stdout.splitlines(), ctx.scope)
        elif name == "amass":
            output = ctx.run_dir / "amass.txt"
            command = tool_command(ctx, name, "enum", "-passive", "-d", ctx.config.target, "-o", str(output))
            result = run_cmd(command, ctx.logger, timeout=ctx.config.command_timeout) if command else None
            values = collect_host_values(read_lines(output), ctx.scope) if output.exists() else set()
            if result and result.stdout:
                values |= collect_host_values(result.stdout.splitlines(), ctx.scope)
        else:
            command = tool_command(ctx, name, "--subs-only", ctx.config.target)
            result = run_cmd(command, ctx.logger, timeout=300) if command else None
            values = collect_host_values((result.stdout if result else "").splitlines(), ctx.scope)
            write_lines(ctx.run_dir / "assetfinder.txt", values)
        if values:
            discovered |= values
            sources[name] = len(values)
        elif not ctx.tools.get(name):
            ctx.logger.warn(f"{name} unavailable; skipping")

    crt_values = crtsh_subdomains(ctx)
    discovered |= crt_values
    sources["crt.sh"] = len(crt_values)
    write_lines(ctx.run_dir / "subdomains.txt", discovered)
    write_json(ctx.run_dir / "subdomains_sources.json", sources)
    ctx.logger.ok(f"subdomains: {len(discovered)} in-scope hosts")


def parse_httpx_jsonl(path: Path, scope: Scope) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for line in read_lines(path):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = normalize_url(str(entry.get("url", "")), scope)
        if not url:
            continue
        raw_status = entry.get("status_code", entry.get("status-code", entry.get("status", 0)))
        try:
            status = int(raw_status or 0)
        except (TypeError, ValueError):
            status = 0
        tech = entry.get("tech", entry.get("technologies", []))
        if isinstance(tech, list):
            tech = [str(item) for item in tech]
        results.append({
            "url": url,
            "status": status,
            "title": str(entry.get("title", "") or ""),
            "location": str(entry.get("location", entry.get("redirect_location", "")) or ""),
            "technologies": tech,
            "content_length": entry.get("content_length", entry.get("content-length", "")),
        })
    return results


def stage_httpx(ctx: Context) -> None:
    hosts_file = ctx.run_dir / "subdomains.txt"
    hosts = read_lines(hosts_file)
    if not hosts:
        ctx.logger.warn("no subdomains to probe")
        return
    raw_output = ctx.run_dir / "httpx_raw.jsonl"
    command = tool_command(
        ctx,
        "httpx",
        "-l", str(hosts_file),
        "-silent", "-json", "-o", str(raw_output),
        "-status-code", "-title", "-location", "-tech-detect", "-content-length",
        "-threads", str(ctx.config.httpx_threads), "-timeout", "10", "-retries", "1",
    )
    if not command:
        ctx.logger.warn("httpx unavailable; skipping")
        return
    result = run_cmd(command, ctx.logger, timeout=ctx.config.command_timeout)
    records = parse_httpx_jsonl(raw_output, ctx.scope) if raw_output.exists() else []
    write_json(ctx.run_dir / "httpx_results.json", records)
    reachable = [record["url"] for record in records if 200 <= int(record["status"]) < 500]
    successful = [record["url"] for record in records if 200 <= int(record["status"]) < 300]
    screenshot_targets = [record["url"] for record in records if 200 <= int(record["status"]) < 400 or int(record["status"]) in {401, 403, 405}]
    write_lines(ctx.run_dir / "reachable_urls.txt", reachable)
    write_lines(ctx.run_dir / "live_subdomains.txt", successful)
    write_lines(ctx.run_dir / "screenshot_targets.txt", screenshot_targets)
    if not result.ok and not records:
        ctx.logger.warn(f"httpx produced no usable records: {result.stderr[:300]}")
    ctx.logger.ok(f"httpx: {len(records)} records, {len(reachable)} reachable")


def dedupe_urls(urls: Iterable[str], scope: Scope) -> list[str]:
    clean = {url for url in (normalize_url(url, scope) for url in urls) if url}
    return sorted(clean)


def stage_historical(ctx: Context) -> None:
    raw_sources: dict[str, list[str]] = {"waybackurls": [], "gau": []}
    command = tool_command(ctx, "waybackurls")
    if command:
        result = run_cmd(command, ctx.logger, timeout=ctx.config.gau_timeout, input_data=ctx.config.target + "\n")
        raw_sources["waybackurls"] = dedupe_urls(result.stdout.splitlines(), ctx.scope)
    else:
        ctx.logger.warn("waybackurls unavailable; skipping")

    command = tool_command(ctx, "gau", "--threads", "5", "--timeout", "30", "--blacklist", "png,jpg,gif,svg,ico,css,woff,ttf,eot,mp4,mp3,zip", ctx.config.target)
    if command:
        result = run_cmd(command, ctx.logger, timeout=ctx.config.gau_timeout)
        raw_sources["gau"] = dedupe_urls(result.stdout.splitlines(), ctx.scope)
    else:
        ctx.logger.warn("gau unavailable; skipping")

    write_lines(ctx.run_dir / "waybackurls.txt", raw_sources["waybackurls"])
    write_lines(ctx.run_dir / "gau.txt", raw_sources["gau"])
    history = dedupe_urls(raw_sources["waybackurls"] + raw_sources["gau"], ctx.scope)
    write_lines(ctx.run_dir / "historical_urls.txt", history)
    write_json(ctx.run_dir / "historical_sources.json", {key: len(value) for key, value in raw_sources.items()})

    if ctx.config.probe_history and history and ctx.tools.get("httpx"):
        input_file = ctx.run_dir / "historical_probe_input.txt"
        write_lines(input_file, history)
        output_file = ctx.run_dir / "historical_httpx_raw.jsonl"
        command = tool_command(ctx, "httpx", "-l", str(input_file), "-silent", "-json", "-o", str(output_file), "-status-code", "-title", "-threads", "20", "-timeout", "8", "-retries", "1")
        run_cmd(command, ctx.logger, timeout=ctx.config.command_timeout)
        records = parse_httpx_jsonl(output_file, ctx.scope) if output_file.exists() else []
        write_json(ctx.run_dir / "historical_httpx_results.json", records)
        write_lines(ctx.run_dir / "active_historical_endpoints.txt", [record["url"] for record in records if 200 <= int(record["status"]) < 500])
    else:
        atomic_write_text(ctx.run_dir / "active_historical_endpoints.txt", "")


def stage_params(ctx: Context) -> None:
    sources = read_lines(ctx.run_dir / "active_historical_endpoints.txt") + read_lines(ctx.run_dir / "reachable_urls.txt")
    output: set[str] = set()
    names: set[str] = set()
    for url in sources:
        clean = normalize_url(url, ctx.scope)
        if not clean:
            continue
        parsed = urlparse(clean)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        base = parsed._replace(query="", fragment="")
        for key, _ in pairs:
            if not key or len(key) > 100:
                continue
            names.add(key)
            output.add(urlunparse(base._replace(query=urlencode([(key, "")]))))
    write_lines(ctx.run_dir / "params.txt", output)
    write_lines(ctx.run_dir / "parameter_names.txt", names)


def stage_gf(ctx: Context) -> None:
    endpoints = read_lines(ctx.run_dir / "active_historical_endpoints.txt") + read_lines(ctx.run_dir / "reachable_urls.txt")
    endpoints = dedupe_urls(endpoints, ctx.scope)
    if not endpoints:
        ctx.logger.warn("no clean URLs for gf")
        return
    gf_dir = ctx.run_dir / "gf"
    gf_dir.mkdir(exist_ok=True)
    input_data = "\n".join(endpoints) + "\n"
    for pattern in ("xss", "sqli", "ssrf", "redirect", "lfi", "rce", "upload", "idor", "debug", "aws-keys"):
        command = tool_command(ctx, "gf", pattern)
        if not command:
            ctx.logger.warn("gf unavailable; skipping")
            return
        result = run_cmd(command, ctx.logger, timeout=90, input_data=input_data)
        write_lines(gf_dir / f"{pattern}.txt", result.stdout.splitlines())


def is_js_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        return path.endswith(".js") or path.endswith(".mjs")
    except ValueError:
        return False


def stage_katana(ctx: Context) -> None:
    command = ctx.tools.get("katana")
    if not command:
        ctx.logger.warn("katana unavailable; skipping")
        return
    targets = read_lines(ctx.run_dir / "screenshot_targets.txt") or read_lines(ctx.run_dir / "reachable_urls.txt")
    targets = dedupe_urls(targets[: ctx.config.max_targets], ctx.scope)
    if not targets:
        ctx.logger.warn("no in-scope crawl targets")
        return
    targets_file = ctx.run_dir / "katana_targets.txt"
    output_file = ctx.run_dir / "katana_raw.txt"
    write_lines(targets_file, targets)
    args = ["-list", str(targets_file), "-depth", "3", "-js-crawl", "-known-files", "all", "-silent", "-o", str(output_file), "-concurrency", str(ctx.config.katana_concurrency), "-parallelism", "5", "-timeout", "15", "-retry", "1"]
    run_cmd(tool_command(ctx, "katana", *args), ctx.logger, timeout=ctx.config.command_timeout)
    urls = dedupe_urls(read_lines(output_file), ctx.scope) if output_file.exists() else []
    write_lines(ctx.run_dir / "katana_urls.txt", urls)
    write_lines(ctx.run_dir / "js_files.txt", [url for url in urls if is_js_url(url)])
    ctx.logger.ok(f"katana: {len(urls)} in-scope URLs, {len([url for url in urls if is_js_url(url)])} JS files")


def analyze_js_one(ctx: Context, js_url: str) -> dict[str, Any]:
    content = fetch_text(ctx, js_url, max_bytes=ctx.config.max_js_bytes)
    if content is None:
        return {"url": js_url, "urls": [], "endpoints": [], "secrets": []}
    cache_dir = ctx.run_dir / "js" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{sha256_text(js_url)}.js"
    if not cache_file.exists():
        atomic_write_text(cache_file, content)

    urls = {clean for clean in (normalize_url(match.group(0), ctx.scope) for match in URL_RE.finditer(content)) if clean}
    endpoints = set()
    for match in ENDPOINT_RE.finditer(content):
        value = match.group(1)
        if value.startswith("/") and not value.startswith("//"):
            endpoints.add(value)

    secrets: list[dict[str, Any]] = []
    for category, pattern in PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            line = content.count("\n", 0, match.start()) + 1
            secrets.append({
                "category": category,
                "source": js_url,
                "line": line,
                "redacted_value": redact_secret(value),
                "fingerprint": "sha256:" + sha256_text(value),
            })

    finder = tool_command(ctx, "xnLinkFinder", "-i", str(cache_file), "-sp", js_url, "-q")
    if finder:
        result = run_cmd(finder, ctx.logger, timeout=90)
        for line in result.stdout.splitlines():
            clean = normalize_url(line, ctx.scope)
            if clean:
                urls.add(clean)
            elif line.strip().startswith("/"):
                endpoints.add(line.strip())
    return {"url": js_url, "urls": sorted(urls), "endpoints": sorted(endpoints), "secrets": secrets}


def stage_js_analysis(ctx: Context) -> None:
    js_urls = dedupe_urls(read_lines(ctx.run_dir / "js_files.txt"), ctx.scope)
    if not js_urls:
        ctx.logger.warn("no JS files to analyze")
        write_lines(ctx.run_dir / "js_urls.txt", [])
        write_lines(ctx.run_dir / "js_endpoints.txt", [])
        write_json(ctx.run_dir / "js_secrets.json", [])
        return
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.js_workers) as executor:
        futures = [executor.submit(analyze_js_one, ctx, url) for url in js_urls]
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                ctx.logger.warn(f"JS worker failed safely: {exc}")
    all_urls = sorted({url for result in results for url in result["urls"]})
    all_endpoints = sorted({endpoint for result in results for endpoint in result["endpoints"]})
    secret_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in results:
        for secret in result["secrets"]:
            key = (secret["category"], secret["source"], secret["fingerprint"])
            secret_map[key] = secret
    write_lines(ctx.run_dir / "js_urls.txt", all_urls)
    write_lines(ctx.run_dir / "js_endpoints.txt", all_endpoints)
    write_json(ctx.run_dir / "js_secrets.json", list(secret_map.values()))
    ctx.logger.ok(f"JS analysis: {len(all_urls)} URLs, {len(all_endpoints)} endpoints, {len(secret_map)} redacted findings")


def find_eyewitness() -> Optional[list[str]]:
    for name in ("eyewitness", "EyeWitness"):
        path = shutil.which(name)
        if path:
            return [path]
    for base in (Path.home() / "tools" / "EyeWitness", Path("/opt/EyeWitness"), Path.home() / "EyeWitness"):
        for relative in (Path("Python") / "EyeWitness.py", Path("Python3") / "EyeWitness.py"):
            script = base / relative
            if script.exists():
                venv_python = base / "eyewitness-venv" / "bin" / "python"
                return [str(venv_python if venv_python.exists() else Path(sys.executable)), str(script)]
    return None


def stage_eyewitness(ctx: Context) -> None:
    prefix = find_eyewitness()
    targets = ctx.run_dir / "screenshot_targets.txt"
    if not prefix:
        ctx.logger.warn("EyeWitness unavailable; skipping")
        return
    if not targets.exists() or not read_lines(targets):
        ctx.logger.warn("no clean screenshot targets")
        return
    output_dir = ctx.run_dir / "eyewitness"
    output_dir.mkdir(exist_ok=True)
    command = prefix + ["--web", "-f", str(targets), "-d", str(output_dir), "--no-prompt", "--timeout", "15", "--threads", "8", "--delay", "0", "--max-retries", "1"]
    result = run_cmd(command, ctx.logger, timeout=ctx.config.command_timeout)
    reports = list(output_dir.glob("**/report.html"))
    screenshots = list(output_dir.glob("**/*.png"))
    write_json(ctx.run_dir / "eyewitness_summary.json", {"reports": [str(path.relative_to(ctx.run_dir)) for path in reports], "screenshots": len(screenshots), "ok": result.ok})


def stage_summary(ctx: Context) -> None:
    def count(name: str) -> int:
        return len(read_lines(ctx.run_dir / name))

    secrets_path = ctx.run_dir / "js_secrets.json"
    try:
        secrets = json.loads(secrets_path.read_text(encoding="utf-8")) if secrets_path.exists() else []
    except (OSError, json.JSONDecodeError):
        secrets = []
    summary = {
        "target": ctx.config.target,
        "scope": list(ctx.scope.roots),
        "run_dir": str(ctx.run_dir),
        "generated_at": utc_now(),
        "counts": {
            "subdomains": count("subdomains.txt"),
            "reachable_urls": count("reachable_urls.txt"),
            "live_2xx_urls": count("live_subdomains.txt"),
            "historical_urls": count("historical_urls.txt"),
            "active_historical_endpoints": count("active_historical_endpoints.txt"),
            "parameters": count("params.txt"),
            "katana_urls": count("katana_urls.txt"),
            "js_files": count("js_files.txt"),
            "js_urls": count("js_urls.txt"),
            "js_endpoints": count("js_endpoints.txt"),
            "redacted_secret_findings": len(secrets) if isinstance(secrets, list) else 0,
        },
        "stages": ctx.manifest.get("stages", {}),
    }
    write_json(ctx.run_dir / "summary.json", summary)
    rows = "".join(f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>" for key, value in summary["counts"].items())
    page = f"<!doctype html><html lang='en'><meta charset='utf-8'><title>Wildcard Recon — {html.escape(ctx.config.target)}</title><style>body{{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f3f4f6}}</style><h1>Wildcard Recon Summary</h1><p>Target: <b>{html.escape(ctx.config.target)}</b></p><table>{rows}</table><p>Secrets are redacted in the JSON report; review and rotate any confirmed credential.</p></html>"
    atomic_write_text(ctx.run_dir / "summary.html", page)


# ---------------------------------------------------------------------------
# CLI and lifecycle
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Organized, scope-limited reconnaissance workflow")
    parser.add_argument("--target", help="root domain, e.g. example.com")
    parser.add_argument("--scope-file", type=Path, help="optional additional in-scope roots")
    parser.add_argument("--output", type=Path, default=Path("wildcard_runs"), help="output root (default: ./wildcard_runs)")
    parser.add_argument("--profile", choices=("passive", "standard", "deep"), default="standard")
    parser.add_argument("--stages", help="comma-separated stage names, or all")
    parser.add_argument("--skip-stages", help="comma-separated stage names to skip")
    parser.add_argument("--resume", type=Path, help="resume from an existing manifest.json")
    parser.add_argument("--open-browser", action="store_true", help="open OS/browser resources; disabled by default")
    parser.add_argument("--probe-history", action="store_true", help="actively probe historical URLs; disabled by default")
    parser.add_argument("--insecure-tls", action="store_true", help="explicitly disable TLS verification; avoid unless required in a lab")
    parser.add_argument("--dry-run", action="store_true", help="validate and show the workflow without network/tool execution")
    parser.add_argument("--max-targets", type=int, default=50)
    parser.add_argument("--max-js-mb", type=int, default=10)
    parser.add_argument("--quiet", action="store_true")
    return parser


def selected_stages(args: argparse.Namespace) -> tuple[str, ...]:
    if args.stages and args.stages.strip().lower() != "all":
        values = tuple(item.strip() for item in args.stages.split(",") if item.strip())
    else:
        values = STAGE_ORDER
    skipped = {item.strip() for item in (args.skip_stages or "").split(",") if item.strip()}
    unknown = set(values) - set(STAGE_ORDER)
    if unknown or skipped - set(STAGE_ORDER):
        raise ValueError(f"unknown stage(s): {sorted(unknown | (skipped - set(STAGE_ORDER)))}")
    return tuple(stage for stage in values if stage not in skipped)


def load_or_create_context(args: argparse.Namespace, logger_quiet: bool) -> Context:
    if args.resume:
        manifest_path = args.resume
        if manifest_path.is_dir():
            manifest_path = manifest_path / "manifest.json"
        if not manifest_path.exists():
            raise ValueError(f"manifest not found: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        target = normalize_target(str(manifest["target"]))
        scope = Scope(tuple(manifest.get("scope", [target])))
        run_dir = manifest_path.parent
        config_data = manifest.get("config", {})
        config = Config(
            target=target,
            output_root=Path(config_data.get("output_root", str(run_dir.parent.parent))),
            profile=str(config_data.get("profile", "standard")),
            selected_stages=selected_stages(args),
            open_browser=args.open_browser,
            dry_run=args.dry_run,
            resume_manifest=manifest_path,
            insecure_tls=args.insecure_tls,
            probe_history=args.probe_history,
            max_targets=max(1, args.max_targets),
            max_js_bytes=max(1, args.max_js_mb) * 1024 * 1024,
        )
    else:
        raw_target = args.target
        if not raw_target:
            if not sys.stdin.isatty():
                raise ValueError("--target is required in non-interactive mode")
            raw_target = input("Target domain: ").strip()
        target = normalize_target(raw_target)
        scope = build_scope(target, args.scope_file)
        config = Config(
            target=target,
            output_root=args.output,
            profile=args.profile,
            selected_stages=selected_stages(args),
            open_browser=args.open_browser,
            dry_run=args.dry_run,
            insecure_tls=args.insecure_tls,
            probe_history=args.probe_history,
            max_targets=max(1, args.max_targets),
            max_js_bytes=max(1, args.max_js_mb) * 1024 * 1024,
            gau_timeout=900 if args.profile != "deep" else 1800,
            subfinder_threads=20 if args.profile == "passive" else 30,
            httpx_threads=20 if args.profile == "passive" else (50 if args.profile == "deep" else 35),
            katana_concurrency=8 if args.profile == "passive" else (20 if args.profile == "deep" else 15),
            js_workers=4 if args.profile == "passive" else 5,
        )
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        run_dir = config.output_root / safe_filename(target) / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        manifest_path = run_dir / "manifest.json"
        manifest = {
            "version": 2,
            "target": target,
            "scope": list(scope.roots),
            "created_at": utc_now(),
            "config": {key: (str(value) if isinstance(value, Path) else value) for key, value in asdict(config).items() if key not in {"selected_stages", "resume_manifest"}},
            "stages": {},
        }
        write_json(manifest_path, manifest)
        atomic_write_text(config.output_root / safe_filename(target) / "latest_run.txt", str(run_dir) + "\n")
    logger = ReconLogger(run_dir / "recon.log", quiet=logger_quiet)
    tools = detect_tools(logger)
    session = session_for(config)
    return Context(config, scope, run_dir, manifest_path, logger, tools, session, manifest)


def main() -> int:
    print_banner()
    parser = build_parser()
    args = parser.parse_args()
    ctx: Optional[Context] = None
    try:
        ctx = load_or_create_context(args, args.quiet)
        ctx.logger.info(f"target={ctx.config.target}; scope={','.join(ctx.scope.roots)}")
        ctx.logger.info(f"run directory: {ctx.run_dir}")
        functions: dict[str, Callable[[Context], Any]] = {
            "dorks": stage_dorks,
            "whois": stage_whois,
            "subdomains": stage_subdomains,
            "httpx": stage_httpx,
            "historical": stage_historical,
            "params": stage_params,
            "gf": stage_gf,
            "katana": stage_katana,
            "js_analysis": stage_js_analysis,
            "eyewitness": stage_eyewitness,
            "summary": stage_summary,
        }
        for name in STAGE_ORDER:
            if name in ctx.config.selected_stages:
                run_stage(ctx, name, functions[name])
        ctx.logger.info("workflow finished; inspect summary.json and manifest.json")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if ctx:
            ctx.logger.warn("interrupted; partial results and manifest were preserved")
        return 130
    finally:
        if ctx:
            ctx.session.close()
            ctx.logger.close()


if __name__ == "__main__":
    raise SystemExit(main())
