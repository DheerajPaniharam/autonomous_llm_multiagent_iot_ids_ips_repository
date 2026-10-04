#!/usr/bin/env python3
"""
Un-isolate all devices manually:
1. Reset the database `is_isolated` status for all devices back to False.
2. Clear the active firewall rules.
"""
import os
import asyncio
import subprocess

# Load environment variables from .env
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if "=" in line and not line.strip().startswith("#"):
                key, val = line.strip().split("=", 1)
                os.environ[key.strip()] = val.strip().strip("'\"")

from sqlalchemy import update
from backend.database.connection import init_db, session_context, close_db
from backend.database.models import IoTDeviceModel

async def unisolate_all():
    print("[*] Connecting to database...")
    try:
        await init_db()
    except Exception as e:
        print(f"[!] Database connection failed: {e}")
        return

    try:
        # 1. Update database records to set is_isolated = False
        async with session_context() as session:
            stmt = update(IoTDeviceModel).values(is_isolated=False)
            await session.execute(stmt)
            await session.commit()
            print("[+] Successfully reset database isolation status for all devices to Active.")
    except Exception as e:
        print(f"[!] Failed to update database status: {e}")
    finally:
        await close_db()

    # 2. Run reset_firewall.sh to clear rules
    print("[*] Clearing nftables firewall block rules...")
    try:
        # Run reset_firewall.sh using sudo
        result = subprocess.run(["sudo", "bash", "scripts/reset_firewall.sh"], capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Successfully cleared dynamic firewall rules.")
            print(result.stdout)
        else:
            print(f"[!] Failed to run reset_firewall.sh: {result.stderr}")
    except Exception as e:
        print(f"[!] Failed to execute firewall reset: {e}")

    # 3. Clear active rules state file so a restart doesn't restore old rules
    state_file = "state/active_rules.json"
    if os.path.exists(state_file):
        try:
            os.remove(state_file)
            print("[+] Successfully deleted active rules state file.")
        except Exception as e:
            print(f"[!] Failed to delete state file: {e}")

if __name__ == "__main__":
    asyncio.run(unisolate_all())
