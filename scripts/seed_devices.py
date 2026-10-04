#!/usr/bin/env python3
"""
Seeding script to populate the database with mock IoT devices for the demo.
"""
import os
import asyncio
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed_devices")

# Load environment variables from .env
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if "=" in line and not line.strip().startswith("#"):
                key, val = line.strip().split("=", 1)
                os.environ[key.strip()] = val.strip().strip("'\"")

from sqlalchemy import select, func
from backend.database.connection import init_db, session_context, close_db
from backend.database.models import IoTDeviceModel

async def seed():
    print("[*] Connecting to the database...")
    try:
        await init_db()
    except Exception as e:
        print(f"[!] Database connection failed: {e}")
        print("    Please verify that your database is running and DATABASE_URL in '.env' is correct.")
        return

    try:
        async with session_context() as session:
            # Check current devices
            result = await session.execute(select(func.count()).select_from(IoTDeviceModel))
            count = result.scalar() or 0
            
            if count > 0:
                print(f"[+] Found {count} existing devices in the database. Cleaning and re-seeding...")
                # Delete existing to ensure clean seed
                from sqlalchemy import delete
                await session.execute(delete(IoTDeviceModel))
                await session.commit()

            now = datetime.utcnow()
            devices = [
                IoTDeviceModel(
                    device_id="smart-thermostat-01",
                    ip_address="192.168.1.100",
                    mac_address="00:1A:2B:3C:4D:5E",
                    device_type="sensor",
                    protocols=["MQTT", "TCP"],
                    first_seen=now,
                    last_seen=now,
                    is_isolated=False,
                    baseline_packet_rate=12.5,
                    baseline_byte_rate=1024.0,
                ),
                IoTDeviceModel(
                    device_id="security-camera-02",
                    ip_address="192.168.1.101",
                    mac_address="00:1A:2B:3C:4D:5F",
                    device_type="camera",
                    protocols=["RTSP", "HTTP", "TCP"],
                    first_seen=now,
                    last_seen=now,
                    is_isolated=False,
                    baseline_packet_rate=45.0,
                    baseline_byte_rate=81920.0,
                ),
                IoTDeviceModel(
                    device_id="smart-lock-03",
                    ip_address="192.168.1.102",
                    mac_address="00:1A:2B:3C:4D:60",
                    device_type="actuator",
                    protocols=["CoAP", "UDP"],
                    first_seen=now,
                    last_seen=now,
                    is_isolated=False,
                    baseline_packet_rate=2.0,
                    baseline_byte_rate=256.0,
                ),
            ]
            session.add_all(devices)
            await session.commit()
            print(f"[+] Successfully seeded {len(devices)} mock IoT devices in the database.")
            
    except Exception as e:
        print(f"[!] Seeding failed: {e}")
    finally:
        await close_db()

if __name__ == "__main__":
    # Run the async seed function
    # Setup event loop policy for Windows if needed, though this runs in WSL
    asyncio.run(seed())
