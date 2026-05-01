#!/usr/bin/env python3
import asyncio
import websockets
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestIOSConnection")

async def test_connection():
    uri = "ws://localhost:8766"
    logger.info(f"Connecting to {uri}")
    try:
        async with websockets.connect(uri, ping_timeout=10, close_timeout=5) as websocket:
            logger.info("Connected. Registering device...")
            register_msg = {
                "type": "register_device",
                "device_id": "TEST_IOS_001",
                "device_name": "Test iPhone",
                "api_key": "development-key-123",
                "device_type": "iOS",
                "app_version": "2.0",
                "timestamp": datetime.now().isoformat()
            }
            await websocket.send(json.dumps(register_msg))
            response = await websocket.recv()
            resp_data = json.loads(response)
            logger.info(f"Received response: {resp_data}")
            
            if resp_data.get("type") == "registration_success":
                logger.info("✅ Registration successful")
                return True
            else:
                logger.error(f"❌ Registration failed: {resp_data}")
                return False
    except ConnectionRefusedError:
        logger.error("❌ Connection refused. Is cellular_remote_server.py running?")
        return False
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_connection())
    exit(0 if success else 1)
