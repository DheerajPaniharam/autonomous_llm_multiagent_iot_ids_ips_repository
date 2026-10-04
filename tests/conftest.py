"""
Shared pytest configuration and fixtures.

Loads environment variables from .env before any tests run,
ensuring modules that read env vars at import time work correctly.
"""
import os
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

_CASE_LOG_DIR: Path | None = None


def pytest_configure(config):
    global _CASE_LOG_DIR
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    configured_log_dir = os.environ.get("PYTEST_CASE_LOG_DIR")
    _CASE_LOG_DIR = (
        Path(configured_log_dir)
        if configured_log_dir
        else Path(config.rootpath) / "logs" / "test_cases" / f"run-{run_id}-{os.getpid()}"
    )
    _CASE_LOG_DIR.mkdir(parents=True, exist_ok=True)


def pytest_runtest_logreport(report):
    if _CASE_LOG_DIR is None:
        return

    safe_nodeid = re.sub(r"[^A-Za-z0-9_.-]+", "_", report.nodeid).strip("_")[:120]
    nodeid_hash = hashlib.sha256(report.nodeid.encode("utf-8")).hexdigest()[:10]
    log_path = _CASE_LOG_DIR / f"{safe_nodeid}-{nodeid_hash}.log"
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{report.when}] outcome={report.outcome} duration={report.duration:.6f}s\n")
        for section_name, content in report.sections:
            log_file.write(f"\n--- {section_name} ---\n{content}\n")
        if report.failed:
            log_file.write(f"\n--- failure ---\n{report.longrepr}\n")
        log_file.write("\n")

# ---------------------------------------------------------------------------
# Load .env before any test module is imported
# ---------------------------------------------------------------------------

def _load_dotenv():
    """Parse .env file and set environment variables if not already set."""
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            # Skip comments and blank lines
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Only set if not already present in the environment
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()
# Tests mock nftables subprocess calls and must not inherit the development
# machine's simulation setting from .env.
os.environ["FIREWALL_MODE"] = "production"
os.environ["FIREWALL_EXECUTOR_SOCKET"] = ""
# Provide a default JWT secret for test execution so auth modules can import safely.
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
