import asyncio
from backend.database.connection import init_db, session_context
from backend.database.models import IoTDeviceModel
from sqlalchemy import select

async def main():
    try:
        await init_db()
        async with session_context() as session:
            devices = (await session.execute(select(IoTDeviceModel))).scalars().all()
            for d in devices:
                print(f"Device: {d.device_id} | IP: {d.ip_address} | Isolated: {d.is_isolated}")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    asyncio.run(main())
