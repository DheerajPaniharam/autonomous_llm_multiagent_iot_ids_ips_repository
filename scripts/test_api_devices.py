import os
import sys

# Load env variables from .env, but do not overwrite variables already set (e.g., by docker-compose)
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if "=" in line and not line.strip().startswith("#"):
                key, val = line.strip().split("=", 1)
                key = key.strip()
                # Do not overwrite existing environment variables (docker-compose sets DATABASE_URL)
                if key in os.environ:
                    continue
                os.environ[key] = val.strip().strip("'\"")

# Force using local host connection for testing when running tests outside Docker.
# When running inside the `api` container, avoid rewriting the URL so the tests
# connect to the composed `db` service using the service hostname.
if "DATABASE_URL" in os.environ:
    url = os.environ["DATABASE_URL"]
    running_in_container = os.path.exists("/.dockerenv") or os.environ.get("IN_DOCKER")
    if not running_in_container:
        # If it is connecting to docker container db:5432, rewrite it to localhost:5433 for external test
        if "@db:5432" in url:
            os.environ["DATABASE_URL"] = url.replace("@db:5432", "@localhost:5433")
        elif "@localhost:5432" in url:
            os.environ["DATABASE_URL"] = url.replace("@localhost:5432", "@localhost:5433")

from fastapi.testclient import TestClient
from backend.main import app

print(f"[*] Testing database connection using: {os.environ.get('DATABASE_URL')}")

# Wrap client in a 'with' block to trigger FastAPI lifespan/init_db
with TestClient(app) as client:
    # Try logging in
    print("[*] Logging in as admin...")
    login_resp = client.post("/auth/token", data={"username": "admin", "password": "admin123"})
    print(f"    Status: {login_resp.status_code}")
    if login_resp.status_code != 200:
        print(f"    Failed: {login_resp.text}")
        sys.exit(1)

    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Query devices
    print("[*] Querying /api/v1/devices...")
    devices_resp = client.get("/api/v1/devices", headers=headers)
    print(f"    Status: {devices_resp.status_code}")
    print(f"    Response JSON: {devices_resp.json()}")
